import ctypes
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from core import (Candidate, Rule, Snapshot, cache_rules, clean, delete_permanently,
                  describe_file, export_report, plain_path, scan, validate_file)


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='diskreview-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cache = self.root / 'cache'
        self.cache.mkdir()
        self.roots = [str(self.root)]
        self.rule = Rule(str(self.cache), '测试缓存', '测试生成的缓存', '可清理')

    def file(self, name, content=b'old cache', old=True):
        path = self.cache / name
        path.write_bytes(content)
        if old:
            modified = time.time() - 30 * 86400
            os.utime(path, (modified, modified))
        return path

    def snapshot(self, path):
        return Snapshot.capture(str(path), path.stat())

    def scan_cache(self):
        return scan(self.roots, [self.rule], cache_min=1, file_min=1, age_days=7)

    def test_retention_and_selected_scope(self):
        old = self.file('old.txt')
        recent = self.file('new.txt', old=False)
        outside = self.root / 'keep.txt'
        outside.write_text('keep')
        result = self.scan_cache()
        self.assertEqual(len(result.candidates), 1)
        candidate = result.candidates[0]
        self.assertEqual(candidate.total_files, 2)
        self.assertEqual([f.path for f in candidate.files], [str(old)])
        summary = clean([candidate], self.roots, '永久删除', self.root / 'log.jsonl')
        self.assertEqual(summary['success'], 1, summary)
        self.assertFalse(old.exists())
        self.assertTrue(recent.exists())
        self.assertTrue(outside.exists())
        self.assertTrue(self.cache.is_dir())

    def test_changed_file_is_not_deleted(self):
        path = self.file('changed.txt')
        candidate = self.scan_cache().candidates[0]
        path.write_text('new content after the scan')
        summary = clean([candidate], self.roots, '永久删除', self.root / 'log.jsonl')
        self.assertEqual(summary['skipped'], 1)
        self.assertTrue(path.exists())

    @unittest.skipUnless(os.name == 'nt', 'Windows DirEntry metadata test')
    def test_change_during_scan_is_rejected(self):
        path = self.file('racing.txt')
        with os.scandir(self.cache) as entries:
            entry = next(entries)
            previous = entry.stat(follow_symlinks=False)
        path.write_text('new content written during scan')
        with self.assertRaises(OSError):
            Snapshot.capture(str(path), previous)
        self.assertTrue(path.exists())

    def test_replaced_file_identity_is_checked(self):
        path = self.file('replaced.txt')
        before = self.snapshot(path)
        replacement = self.file('replacement.txt')
        os.utime(replacement, ns=(before.modified_ns, before.modified_ns))
        os.replace(replacement, path)
        with self.assertRaises(ValueError):
            validate_file(before, self.roots)

    def test_hardlinks_are_not_deleted(self):
        path = self.file('original.txt')
        sibling = self.cache / 'hardlink.txt'
        os.link(path, sibling)
        with self.assertRaises(ValueError):
            delete_permanently(self.snapshot(path), self.roots)
        self.assertTrue(path.exists())
        self.assertTrue(sibling.exists())

    def test_root_and_outside_paths_rejected(self):
        with self.assertRaises(ValueError):
            plain_path(str(self.root), self.roots)
        with self.assertRaises(ValueError):
            plain_path(str(self.root.parent / 'outside.txt'), self.roots)

    def test_linked_ancestor_rejected(self):
        path = self.file('keep.txt')
        original = os.lstat
        class LinkInfo:
            st_mode = stat.S_IFDIR
            st_file_attributes = 0x400
        def linked(value):
            if os.path.normcase(os.fspath(value)) == os.path.normcase(str(self.cache)):
                return LinkInfo()
            return original(value)
        with patch('core.os.lstat', side_effect=linked):
            with self.assertRaises(ValueError):
                validate_file(self.snapshot(path), self.roots)
        self.assertTrue(path.exists())

    def test_duplicate_selection_is_processed_once(self):
        self.file('old.txt')
        candidate = self.scan_cache().candidates[0]
        summary = clean([candidate, candidate], self.roots, '永久删除', self.root / 'log.jsonl')
        self.assertEqual(summary['success'], 1)
        self.assertEqual(summary['skipped'], 0)

    def test_protected_rule_cannot_be_selected(self):
        path = self.file('system.txt')
        rule = Rule(str(self.cache), '系统管理', '由系统管理', '使用存储设置', managed=True)
        result = scan(self.roots, [rule], cache_min=1)
        candidate = result.candidates[0]
        self.assertFalse(candidate.selectable)
        summary = clean([candidate], self.roots, '永久删除', self.root / 'log.jsonl')
        self.assertEqual(summary['success'], 0)
        self.assertTrue(path.exists())

    def test_credentials_inside_cache_are_never_selected_or_deleted(self):
        secret = self.file('.env', b'PRIVATE_TEST_VALUE')
        result = self.scan_cache()
        self.assertEqual(result.candidates[0].files, [])
        with self.assertRaises(ValueError):
            validate_file(self.snapshot(secret), self.roots)
        self.assertTrue(secret.exists())

    def test_export_is_anonymous_unless_explicitly_requested(self):
        self.file('private-account-name.txt')
        result = self.scan_cache()
        output = self.root / 'summary.json'
        export_report(result, output)
        summary = output.read_text(encoding='utf-8')
        self.assertNotIn('private-account-name', summary)
        self.assertNotIn(str(self.root), summary)
        self.assertEqual(json.loads(summary)['privacy'], 'summary')
        export_report(result, output, include_private=True)
        self.assertEqual(json.loads(output.read_text(encoding='utf-8'))['items'][0]['path'], str(self.cache))

    def test_full_scan_does_not_duplicate_cache_files(self):
        self.file('large.log')
        result = scan(self.roots, [self.rule], full=True, cache_min=1, file_min=1)
        self.assertEqual(len(result.candidates), 1)
        self.assertEqual(result.candidates[0].path, str(self.cache))

    def test_cancel_does_not_delete(self):
        path = self.file('old.txt')
        candidate = self.scan_cache().candidates[0]
        event = threading.Event()
        event.set()
        result = clean([candidate], self.roots, '永久删除', self.root / 'log.jsonl', cancel=event)
        self.assertTrue(result['cancelled'])
        self.assertTrue(path.exists())

    def test_unselected_candidates_untouched(self):
        path = self.file('keep.txt')
        result = clean([], self.roots, '永久删除', self.root / 'log.jsonl')
        self.assertEqual(result['success'], 0)
        self.assertTrue(path.exists())

    def test_recycle_mode_dispatch_does_not_permanently_delete(self):
        path = self.file('installer.zip')
        for category in ('安装包/资料', '个人文件', '未完成下载', '日志/诊断'):
            with self.subTest(category=category):
                candidate = Candidate(str(path), '普通文件', category, '用户资料', '确认后清理',
                                      path.stat().st_size, 1, files=[self.snapshot(path)])
                with patch('core.recycle_file') as recycle, patch('core.delete_permanently') as permanent:
                    result = clean([candidate], self.roots, '推荐方式', self.root / 'log.jsonl')
                recycle.assert_called_once()
                permanent.assert_not_called()
                self.assertEqual(result['recycled_bytes'], path.stat().st_size)

    def test_recommended_cache_cleanup_is_permanent(self):
        path = self.file('cache.txt')
        for category in ('缓存', '更新包'):
            with self.subTest(category=category):
                candidate = Candidate(str(path), '缓存文件', category, '可重建缓存', '确认后清理',
                                      path.stat().st_size, 1, files=[self.snapshot(path)])
                with patch('core.recycle_file') as recycle, patch('core.delete_permanently') as permanent:
                    result = clean([candidate], self.roots, '推荐方式', self.root / 'log.jsonl')
                permanent.assert_called_once()
                recycle.assert_not_called()
                self.assertEqual(result['deleted_bytes'], path.stat().st_size)

    @unittest.skipUnless(os.name == 'nt', 'Windows exclusive handle test')
    def test_locked_file_is_skipped(self):
        path = self.file('locked.txt')
        snapshot = self.snapshot(path)
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong,
                                      ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p]
        kernel.CreateFileW.restype = ctypes.c_void_p
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel.CreateFileW(str(path), 0x80000000, 0, None, 3, 0, None)
        self.assertNotEqual(handle, ctypes.c_void_p(-1).value)
        try:
            with self.assertRaises(OSError):
                delete_permanently(snapshot, self.roots)
        finally:
            kernel.CloseHandle(handle)
        self.assertTrue(path.exists())


class ClassificationTests(unittest.TestCase):
    def test_personal_and_system_data_protected(self):
        for path in (r'C:\Windows\0', r'C:\pagefile.sys',
                     r'C:\Users\Example\Documents\xwechat_files\account\media.db',
                     r'D:\OllamaModels\blobs\sha256-test', r'D:\vivado\data\library.zip',
                     r'D:\project\.git\objects\pack\large.pack', r'D:\unknown.dat',
                     r'D:\$RECYCLE.BIN\user\archive.zip', r'C:\ProgramData\Tool\data.zip'):
            with self.subTest(path=path):
                self.assertTrue(describe_file(path)[3])

    def test_real_downloads_and_logs_can_be_reviewed(self):
        for path in (r'D:\downloads\SolidWorks 2026.zip', r'D:\project\sim_verilator\spike_diff.log',
                     r'D:\downloads\setup.exe.baiduyun.p.downloading'):
            with self.subTest(path=path):
                self.assertFalse(describe_file(path)[3])

    def test_rules_do_not_target_entire_personal_or_runtime_directories(self):
        for rule in cache_rules(r'C:\Users\Example'):
            normalized = rule.path.replace('\\', '/').lower()
            self.assertNotIn('xwechat_files', normalized)
            self.assertNotIn('codex-runtimes', normalized)
            self.assertNotIn('node_modules', normalized)
            if normalized.endswith('softwaredistribution/download'):
                self.assertTrue(rule.managed)


if __name__ == '__main__':
    unittest.main()

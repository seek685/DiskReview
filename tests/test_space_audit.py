import os
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import tkinter as tk
import unittest
from unittest.mock import Mock, patch

from core import Rule, cache_rules, key
from space_audit import Audit, Usage, audit_drive, explain, recommendations
from space_view import SpaceWindow


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='diskreview-audit-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_small_files_aggregate_and_large_file_is_not_counted_twice(self):
        child = self.root / 'one' / 'two'
        child.mkdir(parents=True)
        (child / 'a.txt').write_bytes(b'a' * 4)
        (child / 'b.txt').write_bytes(b'b' * 6)
        (self.root / 'large.bin').write_bytes(b'x' * 12)
        result = audit_drive(str(self.root), large_file=10)
        top = result.nodes[key(self.root)]
        self.assertEqual((top.size, top.files), (22, 3))
        self.assertEqual(result.nodes[key(child.parent)].size, 10)
        self.assertEqual(sum(n.size for n in result.children(str(self.root))), 22)
        self.assertEqual(result.children(str(self.root))[0].path, str(self.root / 'large.bin'))

    def test_skip_reparse_directory_without_visiting_target(self):
        entry = Mock(path=str(self.root / 'link'))
        entry.stat.return_value = Mock(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
        entries = Mock()
        entries.__enter__ = Mock(return_value=iter([entry]))
        entries.__exit__ = Mock(return_value=False)
        with patch('space_audit.os.scandir', return_value=entries) as scanner:
            result = audit_drive(str(self.root))
        self.assertEqual(scanner.call_count, 1)
        self.assertEqual(result.nodes[key(self.root)].links, 1)
        self.assertNotIn(key(entry.path), result.nodes)

    def test_unreadable_directory_marks_ancestor_and_keeps_other_bytes(self):
        blocked = self.root / 'blocked'
        blocked.mkdir()
        (self.root / 'keep.txt').write_bytes(b'keep')
        original = os.scandir
        def scanner(path):
            if key(path) == key(blocked):
                raise PermissionError('test access denied')
            return original(path)
        with patch('space_audit.os.scandir', side_effect=scanner):
            result = audit_drive(str(self.root))
        top = result.nodes[key(self.root)]
        self.assertEqual((top.size, top.errors), (4, 1))
        self.assertEqual(result.nodes[key(blocked)].errors, 1)
        self.assertIn('test access denied', result.errors[0])

    def test_cancelled_scan_is_partial_and_has_no_cleanup_recommendations(self):
        stop = threading.Event()
        stop.set()
        result = audit_drive(str(self.root), cancel=stop)
        self.assertTrue(result.cancelled)
        self.assertEqual(recommendations(result, str(self.root)), [])

    def test_system_personal_and_unknown_cache_names_are_not_safe_cache(self):
        for path in (r'C:\Windows\WinSxS', r'C:\Windows\Installer', r'C:\pagefile.sys',
                     r'C:\Users\Example\Documents\xwechat_files',
                     r'C:\Users\Example\.cache\huggingface', r'C:\Users\Example\AppData\Local\Unknown\Cache',
                     r'C:\Users\Example\AppData\Roaming\Code\Backups'):
            with self.subTest(path=path):
                self.assertNotEqual(explain(path, r'C:\Users\Example', [])[0], '可清理缓存')
        self.assertEqual(explain(r'C:\Windows\Installer', r'C:\Users\Example', [])[0], '系统管理')
        self.assertEqual(explain(r'C:\Program Files\Tool', r'C:\Users\Example', [])[0], '卸载 / 不手删')
        self.assertEqual(explain(r'C:\Users\Example\.cache\codex-runtimes', r'C:\Users\Example', [])[0], '卸载 / 不手删')
        self.assertEqual(explain(r'C:\Users\Example\.vscode\extensions', r'C:\Users\Example', [])[0], '卸载 / 不手删')

    def test_explicit_cache_rule_overrides_mixed_appdata_description(self):
        cache = self.root / 'AppData' / 'Local' / 'Temp'
        rule = Rule(str(cache), '临时缓存', '用途', '建议')
        self.assertEqual(explain(str(cache / 'sub'), str(self.root), [rule])[0], '可清理缓存')

    def test_recommendations_never_double_count_parent_and_child(self):
        a, b = self.root / 'cache', self.root / 'cache' / 'child'
        result = Audit(str(self.root), {key(a): Usage(str(a), size=30), key(b): Usage(str(b), size=20)})
        rules = [Rule(str(p), '缓存', '用途', '建议') for p in (a, b)]
        self.assertEqual([n.path for n in recommendations(result, str(self.root), rules)], [str(a)])
        result.nodes[key(a)].errors = 1
        self.assertEqual([n.path for n in recommendations(result, str(self.root), rules)], [str(b)])

    def test_browser_profiles_only_expose_cache_directories(self):
        profile = self.root / 'AppData' / 'Local' / 'Google' / 'Chrome' / 'User Data' / 'Profile 2'
        (profile / 'Cache').mkdir(parents=True)
        rules = cache_rules(str(self.root))
        paths = {key(r.path) for r in rules}
        self.assertIn(key(profile / 'Cache'), paths)
        self.assertNotIn(key(profile), paths)
        self.assertNotIn(key(profile / 'Login Data'), paths)

    def test_cli_space_report_is_private_by_default_and_keeps_cache_report_separate(self):
        (self.root / 'sample.txt').write_bytes(b'data')
        local = self.root / 'report-home'
        result = subprocess.run([sys.executable, '-X', 'utf8', '-B',
                                 str(Path(__file__).resolve().parents[1] / 'app.py'),
                                 '--scan', 'space', '--root', str(self.root)],
                                env={**os.environ, 'LOCALAPPDATA': str(local)},
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        directory = local / 'DiskReview' / 'reports'
        report = json.loads((directory / 'latest-space-summary.json').read_text(encoding='utf-8'))
        self.assertEqual(report['logical_bytes'], 4)
        self.assertNotIn('directories_and_large_files', report)
        self.assertNotIn(str(self.root), result.stdout)
        self.assertFalse((directory / 'latest-scan.json').exists())


class SpaceInterfaceTests(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.root.withdraw()
        self.callback = Mock(return_value=True)
        self.view = SpaceWindow(self.root, r'C:\Users\Example', self.callback)
        root = Usage('C:\\', size=100, files=2)
        child = Usage(r'C:\Windows', key(root.path), size=100, files=2)
        self.view.result = Audit(root.path, {key(root.path): root, key(child.path): child}, total=1000, free=200)
        self.view.render()
        self.addCleanup(self.destroy)

    def destroy(self):
        self.view.busy = False
        self.view.close()
        self.root.destroy()

    def test_window_controls_visible_and_details_identify_system_directory(self):
        self.view.window.geometry('1000x650+20+20')
        self.root.update()
        for button in (self.view.scan_button, self.view.stop_button, self.view.cache_button):
            self.assertTrue(button.winfo_ismapped())
            x = button.winfo_rootx() - self.view.window.winfo_rootx()
            y = button.winfo_rooty() - self.view.window.winfo_rooty()
            self.assertLessEqual(x + button.winfo_width(), self.view.window.winfo_width())
            self.assertLessEqual(y + button.winfo_height(), self.view.window.winfo_height())
        tree = self.view.trees[1]
        top = tree.get_children()[0]
        child = tree.get_children(top)[0]
        tree.selection_set(child)
        self.view.show_detail(tree)
        text = self.view.detail.get('1.0', 'end')
        self.assertIn('系统管理', text)
        self.assertIn('不可手动删除', text)

    def test_cache_button_opens_review_without_deleting_or_selecting_anything(self):
        self.view.cache_button.invoke()
        self.callback.assert_called_once_with()

    def test_close_while_scanning_requests_cancel(self):
        self.view.busy = True
        self.view.close()
        self.assertTrue(self.view.cancel.is_set())
        self.assertTrue(self.view.window.winfo_exists())


if __name__ == '__main__':
    unittest.main()

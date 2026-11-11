from pathlib import Path
import tempfile
import time
import tkinter as tk
import unittest
from unittest.mock import patch

from app import App
from core import Candidate, ScanResult, Snapshot


class InterfaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='diskreview-ui-test-')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'cache.txt'
        self.path.write_text('test only')
        snapshot = Snapshot.capture(str(self.path), self.path.stat())
        self.candidate = Candidate(str(self.path.parent), '测试缓存', '缓存', '测试用途', '测试建议',
                                   snapshot.size, 1, time.time(), [snapshot])
        self.protected = Candidate(str(self.path.parent / 'system'), '系统保护', '保护项', '系统文件',
                                   '不能直接删除', 1234, 1, time.time(), protected=True)
        self.root = tk.Tk()
        self.root.withdraw()
        self.app = App(self.root)
        self.app.result = ScanResult([self.candidate, self.protected], 2, [], 0, False, 0)
        self.app.render()
        self.addCleanup(self.destroy)

    def destroy(self):
        for callback in self.root.tk.call('after', 'info'):
            self.root.after_cancel(callback)
        self.root.destroy()

    def test_default_selection_is_empty(self):
        self.assertEqual(self.app.selected, set())
        self.assertEqual(self.app.mode.get(), '全部回收站')
        self.assertEqual(self.app.tree.set('0', 'check'), '☐')
        self.assertEqual(str(self.app.clean_button['state']), 'disabled')

    def test_cleanup_controls_stay_visible_in_small_window(self):
        self.root.deiconify()
        for width, height in ((1000, 620), (1100, 700), (1320, 860)):
            with self.subTest(width=width, height=height):
                self.root.geometry(f'{width}x{height}+20+20')
                self.root.update()
                for widget in (self.app.clean_button, self.app.mode_combo, self.app.apps_button, self.app.c_button):
                    self.assertTrue(widget.winfo_ismapped(), '清理操作控件被挤出窗口')
                    x = widget.winfo_rootx() - self.root.winfo_rootx()
                    y = widget.winfo_rooty() - self.root.winfo_rooty()
                    self.assertGreaterEqual(x, 0)
                    self.assertGreaterEqual(y, 0)
                    self.assertLessEqual(x + widget.winfo_width(), self.root.winfo_width())
                    self.assertLessEqual(y + widget.winfo_height(), self.root.winfo_height())

    def test_cleanup_button_opens_confirmation_and_cancel_keeps_file(self):
        self.app.toggle('0')
        self.assertEqual(str(self.app.clean_button['state']), 'normal')
        with patch('app.messagebox.askyesno', return_value=False) as confirmation, patch('app.clean') as cleaner:
            self.app.clean_button.invoke()
        confirmation.assert_called_once()
        cleaner.assert_not_called()
        self.assertTrue(self.path.exists())

    def test_toggle_and_detail_and_clear(self):
        self.app.toggle('0')
        self.assertEqual(self.app.selected, {0})
        self.assertEqual(self.app.tree.set('0', 'check'), '☑')
        self.app.tree.selection_set('0')
        self.app.show_detail()
        self.assertIn('测试用途', self.app.detail.get('1.0', 'end'))
        self.app.clear_selection()
        self.assertEqual(self.app.selected, set())

    def test_protected_item_cannot_be_checked(self):
        self.app.toggle('1')
        self.assertEqual(self.app.selected, set())
        self.assertEqual(self.app.tree.set('1', 'check'), '—')

    def test_filtered_select_only_affects_visible_cache(self):
        self.app.search.set('系统保护')
        self.app.render()
        self.app.select_visible_caches()
        self.assertEqual(self.app.selected, set())
        self.app.search.set('测试缓存')
        self.app.render()
        self.app.select_visible_caches()
        self.assertEqual(self.app.selected, {0})

    def test_cancel_confirmation_never_starts_cleanup(self):
        self.app.toggle('0')
        with patch('app.messagebox.askyesno', return_value=False), patch('app.clean') as cleaner:
            self.app.start_cleanup()
        cleaner.assert_not_called()
        self.assertTrue(self.path.exists())
        self.assertFalse(self.app.busy)

    def test_no_selection_cannot_start_cleanup(self):
        with patch('app.messagebox.askyesno') as confirmation, patch('app.clean') as cleaner:
            self.app.start_cleanup()
        confirmation.assert_not_called()
        cleaner.assert_not_called()

    def test_completed_result_requires_new_scan(self):
        self.app.stale = True
        self.app.toggle('0')
        self.assertEqual(self.app.selected, set())


if __name__ == '__main__':
    unittest.main()

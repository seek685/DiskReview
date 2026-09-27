import os
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import unittest
from unittest.mock import patch

from app_inventory import (Inventory, Location, measure, recycle_locations, related_processes,
                           scan_apps, selected_roots, discover_locations, export_inventory)
from app_view import AppStorageWindow
from windows_ops import Process, process_inventory, stop_confirmed_processes


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='diskreview-app-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / 'Demo'
        self.data.mkdir()
        (self.data / 'personal.db').write_bytes(b'x' * 17)
        (self.data / 'Cache').mkdir()
        (self.data / 'Cache' / 'page').write_bytes(b'x' * 23)
        self.roots = [str(self.root)]
        self.location = Location('Demo', str(self.data), '应用数据', '测试数据库')

    def inventory(self):
        return scan_apps(str(self.root), self.roots, locations=[self.location])

    def test_cache_included_in_data_total_not_double_counted(self):
        inv = self.inventory()
        self.assertEqual(len(inv.locations), 2)
        self.assertEqual(inv.totals()['Demo'], {'total': 40, 'data': 40, 'program': 0, 'cache': 23})
        self.assertEqual(selected_roots(inv.locations), [self.location])

    def test_export_is_anonymous_unless_explicitly_requested(self):
        inv = self.inventory()
        output = self.root / 'summary.json'
        export_inventory(inv, output)
        summary = output.read_text(encoding='utf-8')
        self.assertNotIn(str(self.data), summary)
        self.assertNotIn('Demo', summary)
        self.assertEqual(json.loads(summary)['privacy'], 'summary')
        export_inventory(inv, output, include_private=True)
        self.assertEqual(json.loads(output.read_text(encoding='utf-8'))['locations'][0]['path'], str(self.data))

    def test_credential_directory_is_not_recyclable(self):
        credentials = self.root / '.ssh'
        credentials.mkdir()
        item = Location('Demo', str(credentials), '应用数据', '测试凭据')
        scan_apps(str(self.root), self.roots, locations=[item])
        self.assertFalse(item.selectable)
        with patch('app_inventory.recycle_path') as recycler:
            with self.assertRaises(ValueError):
                recycle_locations([item], self.roots, [], self.root / 'log')
        recycler.assert_not_called()

    def test_data_is_selectable_but_program_is_not(self):
        self.inventory()
        self.assertTrue(self.location.selectable)
        self.location.kind = '程序'
        self.assertFalse(self.location.selectable)
        self.location.kind = '程序/数据混合'
        self.assertFalse(self.location.selectable)

    def test_processes_matched_by_executable_path_not_just_name(self):
        inv = Inventory([], {'Demo': [str(self.data)]}, [])
        inside = Process(700001, 'helper.exe', str(self.data / 'helper.exe'), 1)
        other = Process(700002, 'helper.exe', str(self.root / 'Other' / 'helper.exe'), 2)
        system = Process(700003, 'explorer.exe', str(self.data / 'explorer.exe'), 3)
        self.assertEqual(related_processes([self.location], inv, [inside, other, system]), [inside])

    def test_directory_replacement_blocks_recycle(self):
        self.inventory()
        self.data.rename(self.root / 'saved-data')
        self.data.mkdir()
        with patch('app_inventory.recycle_path') as recycler:
            result = recycle_locations([self.location], self.roots, [], self.root / 'log')
        recycler.assert_not_called()
        self.assertEqual(result['skipped'], 1)

    def test_link_appearing_after_scan_blocks_whole_directory(self):
        self.inventory()
        original = __import__('app_inventory').measure
        def add_issue(loc, *args, **kwargs):
            original(loc, *args, **kwargs)
            loc.issues.append('链接')
        with patch('app_inventory.measure', side_effect=add_issue), patch('app_inventory.recycle_path') as recycler:
            result = recycle_locations([self.location], self.roots, [], self.root / 'log')
        self.assertEqual(result['skipped'], 1)
        recycler.assert_not_called()

    def test_program_never_closed_or_recycled(self):
        self.inventory()
        self.location.kind = '程序'
        with patch('app_inventory.stop_confirmed_processes') as stop, patch('app_inventory.recycle_path') as recycler:
            with self.assertRaises(ValueError):
                recycle_locations([self.location], self.roots, [], self.root / 'log', force=True)
        stop.assert_not_called()
        recycler.assert_not_called()

    def test_regular_recycle_never_closes_processes(self):
        self.inventory()
        with patch('app_inventory.stop_confirmed_processes') as stop, patch('app_inventory.recycle_path') as recycler:
            result = recycle_locations([self.location], self.roots, [], self.root / 'log')
        stop.assert_not_called()
        recycler.assert_called_once_with(str(self.data))
        self.assertEqual(result['success'], 1)

    def test_force_shutdown_finishes_before_recycle(self):
        self.inventory()
        order = []
        processes = [Process(700000, 'demo.exe', str(self.data / 'demo.exe'), 1)]
        with patch('app_inventory.stop_confirmed_processes', side_effect=lambda p, c: order.append(('stop', p)) or []), \
             patch('app_inventory.recycle_path', side_effect=lambda p: order.append(('recycle', p))):
            recycle_locations([self.location], self.roots, processes, self.root / 'log', force=True)
        self.assertEqual(order, [('stop', processes), ('recycle', str(self.data))])

    def test_shutdown_failure_does_not_recycle(self):
        self.inventory()
        with patch('app_inventory.stop_confirmed_processes', side_effect=OSError('access denied')), \
             patch('app_inventory.recycle_path') as recycler:
            with self.assertRaises(OSError):
                recycle_locations([self.location], self.roots, [], self.root / 'log', force=True)
        recycler.assert_not_called()

    def test_cancellation_prevents_directory_recycle(self):
        self.inventory()
        cancel = threading.Event()
        cancel.set()
        with patch('app_inventory.recycle_path') as recycler:
            result = recycle_locations([self.location], self.roots, [], self.root / 'log', cancel=cancel)
        self.assertTrue(result['cancelled'])
        recycler.assert_not_called()

    def test_cancel_before_force_does_not_close_any_process(self):
        self.inventory()
        cancel = threading.Event()
        cancel.set()
        with patch('app_inventory.stop_confirmed_processes') as stop, patch('app_inventory.recycle_path') as recycler:
            result = recycle_locations([self.location], self.roots, [], self.root / 'log', force=True, cancel=cancel)
        self.assertTrue(result['cancelled'])
        stop.assert_not_called()
        recycler.assert_not_called()

    def test_cache_inside_program_does_not_bypass_uninstall(self):
        self.location.kind = '程序'
        inv = self.inventory()
        self.assertTrue(all(not item.selectable for item in inv.locations))

    def test_recycle_failure_preserves_directory_without_fallback(self):
        self.inventory()
        with patch('app_inventory.recycle_path', side_effect=OSError('directory in use')):
            result = recycle_locations([self.location], self.roots, [], self.root / 'log')
        self.assertEqual(result['skipped'], 1)
        self.assertTrue((self.data / 'personal.db').exists())

    def test_duplicate_aliases_are_counted_once(self):
        local = self.root / 'AppData' / 'Local' / 'Ollama'
        local.mkdir(parents=True)
        with patch('app_inventory.installed_locations', return_value=[]):
            locations, _, _ = discover_locations(str(self.root), self.roots)
        self.assertEqual(sum(os.path.normcase(loc.path) == os.path.normcase(str(local)) for loc in locations), 1)


class AppStorageUITests(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.root.withdraw()
        self.app = AppStorageWindow(self.root, str(Path.home()), ['C:\\', 'D:\\'], Path.cwd() / 'reports')
        data = Location('Demo', r'C:\Demo\Data', '应用数据', '用户资料', total_bytes=100, total_files=2, root_identity=(1, 2))
        program = Location('Demo', r'C:\Demo\Program', '程序', '应用程序', total_bytes=200, root_identity=(1, 3))
        self.app.inventory = Inventory([data, program], {}, [])
        self.app.min_mb.set('0')
        self.app.render()
        self.addCleanup(self.destroy)

    def destroy(self):
        for callback in self.root.tk.call('after', 'info'):
            self.app.window.after_cancel(callback)
        self.root.destroy()

    def test_data_can_be_checked_program_cannot(self):
        self.app.toggle('1')
        self.assertFalse(self.app.selected)
        self.app.toggle('0')
        self.assertEqual(self.app.selected, {0})
        self.assertEqual(str(self.app.force_button['state']), 'normal')

    def test_checking_directory_keeps_app_expanded(self):
        parent = self.app.tree.parent('0')
        self.app.tree.item(parent, open=True)
        self.app.toggle('0')
        self.assertTrue(self.app.tree.item(parent, 'open'))

    def test_action_buttons_visible_at_small_size(self):
        self.app.window.geometry('1000x650+20+20')
        self.root.update()
        for widget in (self.app.recycle_button, self.app.force_button):
            self.assertTrue(widget.winfo_ismapped())
            right = widget.winfo_rootx() - self.app.window.winfo_rootx() + widget.winfo_width()
            bottom = widget.winfo_rooty() - self.app.window.winfo_rooty() + widget.winfo_height()
            self.assertLessEqual(right, self.app.window.winfo_width())
            self.assertLessEqual(bottom, self.app.window.winfo_height())

    def test_cancel_confirmation_does_not_start_execution(self):
        self.app.events.put(('prepared', ([self.app.inventory.locations[0]], [], True)))
        with patch.object(self.app, 'confirm', return_value=False), patch.object(self.app, 'execute') as execute:
            self.app.poll()
        execute.assert_not_called()


@unittest.skipUnless(os.name == 'nt', 'Windows process integration')
class ProcessTests(unittest.TestCase):
    def test_confirmed_test_app_releases_lock_then_folder_is_recycled(self):
        with tempfile.TemporaryDirectory(prefix='DiskReview-app-recycle-integration-') as folder:
            root = Path(folder)
            data = root / 'synthetic-app-data'
            data.mkdir()
            (data / 'locked.txt').write_text('DiskReview synthetic test data only')
            ready = root / 'ready'
            child = subprocess.Popen([sys.executable, '-c',
                'import sys,time;from pathlib import Path;f=open(sys.argv[1]);Path(sys.argv[2]).write_text("ready");time.sleep(60)',
                str(data / 'locked.txt'), str(ready)], creationflags=subprocess.CREATE_NO_WINDOW)
            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(ready.exists())
                item = Location('Synthetic Test Only', str(data), '应用数据', '测试数据')
                measure(item, [str(root)])
                confirmed = next(p for p in process_inventory() if p.pid == child.pid)
                result = recycle_locations([item], [str(root)], [confirmed], root / 'log', force=True)
                self.assertEqual(result['success'], 1, result)
                self.assertFalse(data.exists())
                child.wait(timeout=5)
            finally:
                if child.poll() is None:
                    child.terminate()
                child.wait(timeout=5)

    def test_only_confirmed_synthetic_process_is_stopped(self):
        first = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], creationflags=subprocess.CREATE_NO_WINDOW)
        second = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            processes = process_inventory()
            confirmed = next(p for p in processes if p.pid == first.pid)
            stop_confirmed_processes([confirmed])
            first.wait(timeout=5)
            self.assertIsNone(second.poll())
        finally:
            for process in (first, second):
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=5)

    def test_changed_process_identity_not_stopped(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            process = next(p for p in process_inventory() if p.pid == child.pid)
            changed = Process(process.pid, process.name, process.path, process.created - 100000000)
            with self.assertRaises(ValueError):
                stop_confirmed_processes([changed])
            self.assertIsNone(child.poll())
        finally:
            child.terminate()
            child.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()

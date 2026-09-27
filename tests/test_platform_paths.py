import os
from pathlib import Path
import unittest
from unittest.mock import patch

from platform_paths import fixed_drives, report_directory, system_directories, user_directories


class PlatformPathsTests(unittest.TestCase):
    def test_explicit_other_user_does_not_use_current_user_environment(self):
        with patch.dict(os.environ, {'LOCALAPPDATA': r'C:\Private\Local',
                                     'APPDATA': r'C:\Private\Roaming'}):
            local, roaming, documents = user_directories(r'C:\Users\Example')
        self.assertNotIn('Private', local)
        self.assertIn('Example', local)
        self.assertIn('Example', roaming)
        self.assertIn('Example', documents)

    def test_report_directory_is_outside_source_tree(self):
        self.assertNotEqual(report_directory().parent, Path(__file__).resolve().parents[1])

    def test_system_locations_come_from_environment(self):
        with patch.dict(os.environ, {'SystemRoot': r'E:\Windows',
                                     'ProgramFiles': r'E:\Applications'}):
            self.assertEqual(system_directories()[:2], (r'E:\Windows', r'E:\Applications'))

    @unittest.skipUnless(os.name == 'nt', 'Windows drive discovery')
    def test_detected_drives_are_fixed_and_exist(self):
        self.assertTrue(fixed_drives())
        self.assertTrue(all(os.path.isdir(drive) for drive in fixed_drives()))

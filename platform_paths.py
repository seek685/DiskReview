"""Discover local Windows locations without machine-specific installation paths."""
import ctypes
import os
from pathlib import Path


def user_directories(user):
    current = os.path.normcase(os.path.abspath(user)) == os.path.normcase(str(Path.home()))
    local = os.environ.get('LOCALAPPDATA') if current else None
    roaming = os.environ.get('APPDATA') if current else None
    documents = os.path.join(user, 'Documents')
    if current and os.name == 'nt':
        buffer = ctypes.create_unicode_buffer(32768)
        if ctypes.windll.shell32.SHGetFolderPathW(None, 5, None, 0, buffer) == 0:
            documents = buffer.value
    return tuple(os.path.realpath(path) for path in (
        local or os.path.join(user, 'AppData', 'Local'),
        roaming or os.path.join(user, 'AppData', 'Roaming'), documents))


def system_directories():
    drive = os.environ.get('SystemDrive', 'C:')
    return (os.environ.get('SystemRoot', drive + '\\Windows'),
            os.environ.get('ProgramFiles', drive + '\\Program Files'),
            os.environ.get('ProgramFiles(x86)', drive + '\\Program Files (x86)'),
            os.environ.get('ProgramData', drive + '\\ProgramData'))


def fixed_drives():
    if os.name != 'nt':
        return [Path.home().anchor]
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
    mask = kernel.GetLogicalDrives()
    return [f'{chr(65 + index)}:\\' for index in range(26)
            if mask & (1 << index) and kernel.GetDriveTypeW(f'{chr(65 + index)}:\\') == 3]


def report_directory():
    local, _, _ = user_directories(str(Path.home()))
    return Path(local) / 'DiskReview' / 'reports'

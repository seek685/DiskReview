"""Windows recycling and explicitly confirmed process shutdown, without elevation."""
import base64
import ctypes
from ctypes import wintypes as W
from dataclasses import dataclass
import json
import os
import subprocess
import time
import uuid


class GUID(ctypes.Structure):
    _fields_ = [('data', ctypes.c_ubyte * 16)]

    def __init__(self, value):
        super().__init__()
        self.data[:] = uuid.UUID(value).bytes_le


def _method(pointer, index, restype, *argtypes):
    table = ctypes.cast(pointer, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
    return ctypes.WINFUNCTYPE(restype, ctypes.c_void_p, *argtypes)(table[index])


def _check(hr):
    if hr < 0:
        raise OSError(f'Windows 操作失败，代码 0x{hr & 0xffffffff:08X}；文件不会改为永久删除')


def recycle_path(path):
    """Require the Windows Recycle Bin; never fall back to permanent deletion."""
    if os.name != 'nt':
        raise RuntimeError('此功能仅支持 Windows')
    ole = ctypes.OleDLL('ole32')
    shell = ctypes.OleDLL('shell32')
    ole.CoInitializeEx.argtypes = [ctypes.c_void_p, W.DWORD]
    ole.CoInitializeEx.restype = ctypes.c_long
    hr = ole.CoInitializeEx(None, 2)
    initialized = hr >= 0
    if hr < 0 and (hr & 0xffffffff) != 0x80010106:
        _check(hr)
    operation, item = ctypes.c_void_p(), ctypes.c_void_p()
    try:
        ole.CoCreateInstance.argtypes = [ctypes.POINTER(GUID), ctypes.c_void_p, W.DWORD,
                                         ctypes.POINTER(GUID), ctypes.POINTER(ctypes.c_void_p)]
        ole.CoCreateInstance.restype = ctypes.c_long
        _check(ole.CoCreateInstance(ctypes.byref(GUID('3AD05575-8857-4850-9277-11B85BDB8E09')), None, 1,
                                   ctypes.byref(GUID('947AAB5F-0A5C-4C13-B4D6-4BF7836FC9F8')), ctypes.byref(operation)))
        # FOFX_RECYCLEONDELETE, FOFX_EARLYFAILURE, FOFX_NOCOPYHOOKS,
        # FOFX_ADDUNDORECORD and no interactive fallback/error dialogs.
        flags = 0x00080000 | 0x00100000 | 0x00800000 | 0x20000000 | 0x0004 | 0x0010 | 0x0400
        _check(_method(operation, 5, ctypes.c_long, W.DWORD)(operation, flags))
        shell.SHCreateItemFromParsingName.argtypes = [W.LPCWSTR, ctypes.c_void_p, ctypes.POINTER(GUID),
                                                      ctypes.POINTER(ctypes.c_void_p)]
        shell.SHCreateItemFromParsingName.restype = ctypes.c_long
        _check(shell.SHCreateItemFromParsingName(path, None,
               ctypes.byref(GUID('43826D1E-E718-42EE-BC55-A1E261C37BFE')), ctypes.byref(item)))
        _check(_method(operation, 18, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p)(operation, item, None))
        _check(_method(operation, 21, ctypes.c_long)(operation))
        aborted = W.BOOL()
        _check(_method(operation, 22, ctypes.c_long, ctypes.POINTER(W.BOOL))(operation, ctypes.byref(aborted)))
        if aborted.value or os.path.lexists(path):
            raise RuntimeError('目录仍存在或 Windows 已取消回收；未报告为成功，不会永久删除')
    finally:
        for pointer in (item, operation):
            if pointer:
                _method(pointer, 2, W.ULONG)(pointer)
        if initialized:
            ole.CoUninitialize()


@dataclass(frozen=True)
class Process:
    pid: int
    name: str
    path: str
    created: int


def process_inventory():
    command = r"""
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$session = (Get-Process -Id $PID).SessionId
$items = @(Get-CimInstance Win32_Process | Where-Object { $_.SessionId -eq $session -and $_.ExecutablePath } | ForEach-Object {
    [pscustomobject]@{pid=$_.ProcessId;name=$_.Name;path=$_.ExecutablePath;created=$_.CreationDate.ToUniversalTime().ToFileTimeUtc()}
})
ConvertTo-Json -InputObject $items -Compress
"""
    encoded = base64.b64encode(command.encode('utf-16-le')).decode('ascii')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                            capture_output=True, timeout=30,
                            creationflags=subprocess.CREATE_NO_WINDOW, check=True)
    return [Process(int(p['pid']), p['name'], p['path'], int(p['created']))
            for p in json.loads(result.stdout.decode('utf-8-sig'))]


def _kernel():
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
    kernel.OpenProcess.restype = W.HANDLE
    kernel.CloseHandle.argtypes = [W.HANDLE]
    kernel.QueryFullProcessImageNameW.argtypes = [W.HANDLE, W.DWORD, W.LPWSTR, ctypes.POINTER(W.DWORD)]
    kernel.GetProcessTimes.argtypes = [W.HANDLE] + [ctypes.POINTER(W.FILETIME)] * 4
    kernel.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]
    kernel.TerminateProcess.argtypes = [W.HANDLE, W.UINT]
    return kernel


def _confirmed_handle(process):
    if process.pid == os.getpid():
        raise ValueError('不会关闭清理工具自身')
    kernel = _kernel()
    handle = kernel.OpenProcess(0x1000 | 0x0001 | 0x100000, False, process.pid)
    if not handle:
        error = ctypes.get_last_error()
        if error == 87:
            return None
        raise ctypes.WinError(error)
    try:
        name = ctypes.create_unicode_buffer(32768)
        length = W.DWORD(len(name))
        times = [W.FILETIME() for _ in range(4)]
        if not kernel.QueryFullProcessImageNameW(handle, 0, name, ctypes.byref(length)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)):
            raise ctypes.WinError(ctypes.get_last_error())
        created = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
        # WMI converts FILETIME through DateTime (microsecond precision on some versions).
        if os.path.normcase(name.value) != os.path.normcase(process.path) or abs(created - process.created) >= 10:
            raise ValueError('进程身份已改变，不关闭未经确认的新进程')
        return handle
    except Exception:
        kernel.CloseHandle(handle)
        raise


def stop_confirmed_processes(processes, cancel=None):
    """Close only the exact PID, executable and creation time shown in the confirmation."""
    kernel = _kernel()
    user = ctypes.WinDLL('user32', use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
    user.EnumWindows.argtypes = [callback_type, W.LPARAM]
    user.GetWindowThreadProcessId.argtypes = [W.HWND, ctypes.POINTER(W.DWORD)]
    user.PostMessageW.argtypes = [W.HWND, W.UINT, W.WPARAM, W.LPARAM]
    handles, results = [], []
    try:
        for process in processes:
            handle = _confirmed_handle(process)
            if handle:
                handles.append((process, handle))
        pids = {p.pid for p, _ in handles}
        @callback_type
        def close_window(hwnd, _):
            pid = W.DWORD()
            user.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value in pids:
                user.PostMessageW(hwnd, 0x0010, 0, 0)
            return True
        user.EnumWindows(close_window, 0)
        deadline = time.monotonic() + 2
        while any(kernel.WaitForSingleObject(h, 0) == 258 for _, h in handles) and time.monotonic() < deadline:
            if cancel and cancel.is_set():
                raise RuntimeError('已停止；不会强制结束剩余进程')
            time.sleep(0.1)
        for process, handle in handles:
            if cancel and cancel.is_set():
                raise RuntimeError('已停止；不会强制结束剩余进程')
            forced = kernel.WaitForSingleObject(handle, 0) == 258
            if forced and not kernel.TerminateProcess(handle, 1):
                raise ctypes.WinError(ctypes.get_last_error())
            if kernel.WaitForSingleObject(handle, 3000) != 0:
                raise RuntimeError(f'{process.name}（PID {process.pid}）未退出；未继续回收目录')
            results.append({'pid': process.pid, 'name': process.name, 'path': process.path, 'forced': forced})
        return results
    finally:
        for _, handle in handles:
            kernel.CloseHandle(handle)

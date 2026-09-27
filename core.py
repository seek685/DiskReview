"""Local disk inventory and conservative, snapshot-based cleanup. Standard library only."""
import ctypes
from ctypes import wintypes
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import stat
import threading
import time

from platform_paths import report_directory, system_directories, user_directories

MIB = 1024 ** 2
GIB = 1024 ** 3
REPARSE = 0x400
PROTECTED_ROOTS = (str(Path(__file__).resolve().parent), str(report_directory()))


def sensitive_path(path):
    parts = os.fspath(path).replace('\\', '/').casefold().split('/')
    name = parts[-1]
    protected_dirs = {'.ssh', '.aws', '.azure', '.kube', '.gnupg', '.git', '.codex',
                      '.claude', '.gemini', '.deepseek-mcp', '.cc-switch', 'credentials', 'tokenbroker'}
    return (any(part in protected_dirs for part in parts) or
            name == '.env' or name.startswith('.env.') or
            name.startswith(('id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa')) or
            name in {'credentials.json', 'secrets.json', 'auth.json', 'logins.json',
                     'login data', 'cookies', 'key4.db', '.npmrc', '.netrc', '.pypirc'} or
            name.endswith(('.pem', '.key', '.pfx', '.p12', '.kdbx')) or
            any(within(path, root) for root in PROTECTED_ROOTS))


def format_size(value):
    return f'{value / GIB:.2f} GB' if value >= GIB else f'{value / MIB:.1f} MB'


def key(path):
    return os.path.normcase(os.path.abspath(path))


def within(path, root):
    try:
        return os.path.commonpath((key(path), key(root))) == key(root)
    except ValueError:
        return False


def plain_path(path, roots):
    """Validate every ancestor; never follow junctions, symbolic links or cloud placeholders."""
    absolute = os.path.abspath(path)
    if not any(within(absolute, root) and key(absolute) != key(root) for root in roots):
        raise ValueError('目标不在授权扫描盘内，或目标是盘符根目录')
    cursor = Path(absolute)
    for component in reversed((cursor, *cursor.parents)):
        info = os.lstat(component)
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & REPARSE:
            raise ValueError('目录链接/云文件占位符：跳过，避免处理链接目标')
    return absolute


@dataclass(frozen=True)
class Snapshot:
    path: str
    size: int
    modified_ns: int
    device: int
    inode: int

    @classmethod
    def capture(cls, path, info):
        # Windows DirEntry.stat() omits the file ID and volume ID.
        if os.name == 'nt' and not info.st_ino:
            fresh = os.stat(path, follow_symlinks=False)
            if (info.st_size, info.st_mtime_ns) != (fresh.st_size, fresh.st_mtime_ns):
                raise OSError('文件在扫描中发生变化，已跳过')
            info = fresh
        return cls(os.path.abspath(path), info.st_size, info.st_mtime_ns, info.st_dev, info.st_ino)

    def matches(self, info):
        return (self.size, self.modified_ns, self.device, self.inode) == (
            info.st_size, info.st_mtime_ns, info.st_dev, info.st_ino)


@dataclass(frozen=True)
class Rule:
    path: str
    name: str
    purpose: str
    advice: str
    category: str = '缓存'
    managed: bool = False


@dataclass
class Candidate:
    path: str
    name: str
    category: str
    purpose: str
    advice: str
    total_bytes: int = 0
    total_files: int = 0
    latest: float = 0
    files: list = field(default_factory=list)
    protected: bool = False

    @property
    def eligible_bytes(self):
        return sum(f.size for f in self.files)

    @property
    def selectable(self):
        return bool(self.files) and not self.protected


def cache_rules(user):
    local, roaming, _ = user_directories(user)
    windows, _, programs_x86, _ = system_directories()
    rules = []
    def add(base, suffix, name, purpose, advice, category='缓存', managed=False):
        rules.append(Rule(os.path.join(base, *suffix.split('/')), name, purpose, advice, category, managed))
    for base in (local,):
        add(base, 'Temp', '用户临时文件', '程序运行、解压、安装和更新留下的临时文件。', '可考虑；保留近期文件，关闭相关程序后清理。')
        add(base, 'pip/cache', 'Python 下载缓存', 'pip 下载的软件包；不等于已经安装的 Python 库。', '可清理；以后安装依赖需要重新下载。')
        add(base, 'npm-cache', 'npm 下载缓存', 'JavaScript 依赖包下载缓存；不等于 node_modules。', '可清理；以后安装依赖需要重新下载。')
        add(base, 'Arduino15/staging', 'Arduino 下载暂存', 'Arduino/ESP32 开发板支持包和编译工具链的压缩包。', '确认安装完成后可清理；离线重装时需要重新下载。')
        add(base, 'Ollama/updates_v2', 'Ollama 更新安装包', '自动更新下载的安装程序；不是模型。', '确认更新完成后可清理。', '更新包')
        add(base, 'LCEDA-Pro/updater', '嘉立创 EDA 更新包', '软件更新安装程序。', '确认更新完成、不需要回退版本后可清理。', '更新包')
        add(base, 'obsidian-updater', 'Obsidian 更新包', '笔记软件的更新安装程序；不含笔记库。', '确认更新完成后可清理。', '更新包')
        add(base, 'Microsoft/vscode-cpptools', 'VS Code C/C++ 索引', 'C/C++ 扩展的索引和预编译头缓存。', '关闭 VS Code 后可清理；之后会重新建立索引。')
        add(base, 'Google/Chrome/User Data/Default/Cache', 'Chrome 网页缓存', '默认浏览器配置中的网页资源缓存。', '可清理；不处理书签、密码和浏览器整个配置目录。')
        add(base, 'Microsoft/Edge/User Data/Default/Cache', 'Edge 网页缓存', '默认浏览器配置中的网页资源缓存。', '可清理；不处理书签、密码和浏览器整个配置目录。')
        add(base, 'CrashDumps', '应用故障转储', '程序崩溃后生成的诊断文件。', '不再排查对应故障时可清理。', '日志/诊断')
    for base in (roaming,):
        add(base, 'Code/CachedExtensionVSIXs', 'VS Code 插件安装包', '扩展安装包下载缓存；不是已安装的扩展。', '可清理；重装扩展时需要重新下载。')
        add(base, 'Tencent/xwechat/update', '微信更新文件', '微信安装包及版本补丁；不含聊天记录目录。', '退出微信并确认更新完成后可清理。', '更新包')
        add(base, 'Tencent/xwechat/log', '微信运行日志', '记录微信运行和错误信息的日志。', '不再排查对应问题时可清理。', '日志/诊断')
        add(base, 'Tencent/Logs', '腾讯软件日志', '腾讯应用的运行日志。', '不再排查对应问题时可清理。', '日志/诊断')
        add(base, 'LarkShell/update', '飞书更新文件', '飞书自动更新下载内容。', '确认没有正在更新后可清理。', '更新包')
        add(base, 'bilibili/Cache', '哔哩哔哩缓存', '客户端网页资源缓存。', '可清理；不处理手动下载的视频。')
        add(base, 'jlc-assistant/Cache', '嘉立创助手缓存', '客户端网页资源缓存。', '退出程序后可清理，之后会重新生成。')
        add(base, 'Sangfor/aTrust/logs', 'aTrust 连接日志', '深信服客户端运行与连接诊断日志。', '不再排查连接问题时可清理。', '日志/诊断')
    add(user, 'AppData/LocalLow/Intel/ShaderCache', 'Intel 显卡缓存', '图形程序编译的着色器缓存。', '可清理；首次重新运行图形程序可能较慢。')
    add(windows, 'SoftwareDistribution/Download', 'Windows 更新下载', '系统更新包和展开文件；Windows 会继续下载而重新增长。', '使用下方“Windows 存储设置”清理，避免干扰更新。', '系统管理', True)
    add(windows, 'LiveKernelReports', 'Windows 故障转储', '内核、驱动和硬件故障的诊断数据。', '不再排查故障时可清理；权限不足时使用 Windows 存储设置。', '日志/诊断')
    add(programs_x86, 'Google/GoogleUpdater/crx_cache', 'Google 更新缓存', 'Google 软件的更新下载包。', '确认更新完成后可清理；权限不足时由系统处理。', '更新包')
    return rules


def describe_file(path):
    if sensitive_path(path):
        return '保护项', '凭据、私钥、应用认证数据或工具自身文件。', '只统计，不允许清理。', True
    p = path.replace('\\', '/').lower()
    name = os.path.basename(p)
    if p == 'c:/windows/0':
        return '用途待确认', '目录中显示的大文件，但直接访问受限，未确认实际用途。', '不能仅凭文件大小认定为垃圾，暂不清理。', True
    protected_parts = ('/windows/', '/program files/', '/program files (x86)/', '/.git/',
                       '/node_modules/', '/.vscode/extensions/', '/.codex/', '/.cache/codex-runtimes/',
                       '/ollama/lib/', '/vivado/', '/quartus/', '/modelsim/', '/site-packages/',
                       '/programdata/', '/$recycle.bin/', '/system volume information/')
    if name in ('hiberfil.sys', 'pagefile.sys', 'swapfile.sys') or any(x in p for x in protected_parts):
        purpose = '系统或已安装软件的组成部分。'
        if name == 'hiberfil.sys':
            purpose = 'Windows 休眠和快速启动文件。'
        elif name == 'pagefile.sys':
            purpose = 'Windows 虚拟内存分页文件。'
        elif '/.git/' in p:
            purpose = 'Git 仓库历史对象；删除会破坏仓库。'
        return '保护项', purpose, '不建议直接删除；通过系统设置、卸载或所属工具管理。', True
    if '/ollamamodels/' in p or '/.ollama/models/' in p or name.endswith(('.gguf', '.safetensors', '.vhd', '.vhdx', '.vmdk')):
        return '模型/虚拟磁盘', 'AI 模型或虚拟系统磁盘，可能被应用直接使用。', '不按缓存处理；确认不用后在对应软件中管理。', True
    if '/xwechat_files/' in p or name.endswith(('.db', '.sqlite', '.sqlite3', '.pst', '.ost')):
        return '个人数据', '聊天记录、邮件或数据库，可能包含不可替代的个人资料。', '本工具只展示；请在所属软件中管理，不作为普通缓存删除。', True
    if name.endswith(('.dll', '.sys', '.bin', '.pak', '.dat', '.pyd', '.sdbl', '.pack')):
        return '用途待确认', '可能是软件资源、运行库、设备支持包或数据文件。', '无法可靠判断，禁止在此直接清理。', True
    if name.endswith(('.downloading', '.wxdownload', '.crdownload', '.part')):
        return '未完成下载', '下载暂存文件；下载内容尚未完成。', '仅在放弃续传、且下载程序已关闭时清理。', False
    if name.endswith(('.log', '.dmp')):
        purpose = '仿真执行/对比日志。' if '/sim_verilator/' in p else '运行日志或故障诊断数据。'
        return '日志/诊断', purpose, '确认不再需要排查这次运行结果后可清理。', False
    if name.endswith(('.zip', '.rar', '.7z', '.tar.gz', '.iso')):
        label = next((v for k, v in (('solidworks', 'SolidWorks 三维 CAD 安装资料'), ('matlab', 'MATLAB 安装资料'),
                    ('stm32cube', 'STM32Cube 安装包/固件库'), ('pds', 'PDS FPGA 开发工具安装资料'),
                    ('keil', 'Keil/MDK 开发资料'), ('env-windows', 'RT-Thread Env 环境分发包')) if k in p), '压缩包或磁盘镜像')
        return '安装包/资料', label + '；判断依据为路径和文件名，未读取文件内容。', '需要你确认是否保留；可能包含工程或唯一备份，不能自动认定没用。', False
    if name.endswith(('.exe', '.msi')) and ('/downloads/' in p or any(x in name for x in ('setup', 'install'))):
        return '安装包/资料', '疑似安装程序（依据文件名或下载目录）。', '确认已安装、不需要离线重装或回退后可考虑。', False
    if name.endswith(('.mp4', '.mkv', '.mov', '.avi', '.wav', '.pdf', '.psd', '.pptx')):
        return '个人文件', '视频、音频、文档或设计文件；属于个人资料。', '由你判断是否有用；默认移到回收站，可用空间在清空后释放。', False
    return '用途待确认', '仅凭位置和扩展名无法可靠确定用途。', '只展示，不直接清理，避免误删。', True


@dataclass
class ScanResult:
    candidates: list
    scanned_files: int
    errors: list
    skipped_links: int
    cancelled: bool
    seconds: float


def scan(roots, rules, full=False, cache_min=100 * MIB, file_min=500 * MIB,
         age_days=7, progress=lambda _: None, cancel=None):
    cancel = cancel or threading.Event()
    started = time.time()
    cutoff = started - age_days * 86400
    rule_map = {key(r.path): r for r in rules if any(within(r.path, root) for root in roots)}
    aggregates, big_files, errors = {}, [], []
    count = skipped = 0
    last_progress = 0
    if full:
        stack = [(os.path.abspath(root), None) for root in roots if os.path.isdir(root)]
    else:
        stack = []
        for r in rule_map.values():
            try:
                plain_path(r.path, roots)
                stack.append((r.path, r))
            except FileNotFoundError:
                pass
            except ValueError:
                skipped += 1
            except OSError as exc:
                errors.append(f'{r.path}: {exc}')
    while stack and not cancel.is_set():
        folder, active_rule = stack.pop()
        active_rule = rule_map.get(key(folder), active_rule)
        if active_rule and active_rule.path not in aggregates:
            r = active_rule
            aggregates[r.path] = Candidate(r.path, r.name, r.category, r.purpose, r.advice, protected=r.managed)
        try:
            with os.scandir(folder) as entries:
                for entry in entries:
                    if cancel.is_set():
                        break
                    try:
                        info = entry.stat(follow_symlinks=False)
                        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & REPARSE:
                            skipped += 1
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append((entry.path, active_rule))
                            continue
                        count += 1
                        if active_rule:
                            candidate = aggregates[active_rule.path]
                            candidate.total_bytes += info.st_size
                            candidate.total_files += 1
                            candidate.latest = max(candidate.latest, info.st_mtime)
                            if not candidate.protected and not sensitive_path(entry.path) and info.st_mtime <= cutoff and info.st_size:
                                candidate.files.append(Snapshot.capture(entry.path, info))
                        elif full and info.st_size >= file_min:
                            category, purpose, advice, protected = describe_file(entry.path)
                            candidate = Candidate(entry.path, entry.name, category, purpose, advice,
                                                  info.st_size, 1, info.st_mtime, protected=protected)
                            if not protected and info.st_mtime <= cutoff:
                                candidate.files.append(Snapshot.capture(entry.path, info))
                            big_files.append(candidate)
                    except OSError as exc:
                        errors.append(f'{entry.path}: {exc}')
                    if time.monotonic() - last_progress > 0.5:
                        progress(f'已检查 {count:,} 个文件 · {folder}')
                        last_progress = time.monotonic()
        except OSError as exc:
            errors.append(f'{folder}: {exc}')
    candidates = [c for c in aggregates.values() if c.total_bytes >= cache_min] + big_files
    candidates.sort(key=lambda c: c.total_bytes, reverse=True)
    return ScanResult(candidates, count, errors, skipped, cancel.is_set(), time.time() - started)


def validate_file(snapshot, roots):
    if sensitive_path(snapshot.path):
        raise ValueError('凭据、私钥和工具自身文件禁止清理')
    path = plain_path(snapshot.path, roots)
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or not snapshot.matches(info):
        raise ValueError('文件自扫描后发生变化，已跳过，请重新扫描')
    if info.st_nlink > 1:
        raise ValueError('文件存在多个硬链接，已跳过；删除一个路径未必释放空间')
    return path


def delete_permanently(snapshot, roots):
    path = validate_file(snapshot, roots)
    if os.name != 'nt':
        os.unlink(path)
        return
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                  wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    kernel.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.SetFileInformationByHandle.restype = wintypes.BOOL
    # Exclusive handle: in-use files are skipped, never terminate apps or override ACLs.
    handle = kernel.CreateFileW(path, 0x80000000 | 0x10000, 0, None, 3, 0x00200000, None)
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        buffer = ctypes.create_unicode_buffer(32768)
        length = kernel.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
        if not length or length >= len(buffer):
            raise ctypes.WinError(ctypes.get_last_error())
        actual = buffer.value.removeprefix('\\\\?\\')
        if key(actual) != key(path):
            raise ValueError('文件最终路径与扫描路径不符，已跳过')
        # Recheck file identity while holding the exclusive handle.
        import msvcrt
        duplicate = wintypes.HANDLE()
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.DuplicateHandle.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
                                           ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        process = kernel.GetCurrentProcess()
        if not kernel.DuplicateHandle(process, handle, process, ctypes.byref(duplicate), 0, False, 2):
            raise ctypes.WinError(ctypes.get_last_error())
        fd = msvcrt.open_osfhandle(duplicate.value, os.O_RDONLY)
        try:
            if not snapshot.matches(os.fstat(fd)):
                raise ValueError('文件已被替换，已跳过')
        finally:
            os.close(fd)
        delete_flag = ctypes.c_ubyte(1)
        if not kernel.SetFileInformationByHandle(handle, 4, ctypes.byref(delete_flag), ctypes.sizeof(delete_flag)):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.CloseHandle(handle)


def recycle_file(snapshot, roots):
    path = validate_file(snapshot, roots)
    from windows_ops import recycle_path
    recycle_path(path)


def clean(candidates, roots, mode, log_path, progress=lambda _: None, cancel=None):
    if mode not in ('推荐方式', '全部回收站', '永久删除'):
        raise ValueError('未知清理方式')
    cancel = cancel or threading.Event()
    summary = {'deleted_bytes': 0, 'recycled_bytes': 0, 'success': 0, 'skipped': 0, 'errors': [], 'cancelled': False}
    seen = set()
    with open(log_path, 'a', encoding='utf-8') as log:
        for candidate in candidates:
            if not candidate.selectable:
                continue
            is_cache = candidate.category in ('缓存', '更新包')
            permanent = mode == '永久删除' or (mode == '推荐方式' and is_cache)
            for snapshot in candidate.files:
                if cancel.is_set():
                    summary['cancelled'] = True
                    return summary
                if key(snapshot.path) in seen:
                    continue
                seen.add(key(snapshot.path))
                event = {'time': time.strftime('%Y-%m-%d %H:%M:%S'), 'path': snapshot.path,
                         'bytes': snapshot.size, 'action': '永久删除' if permanent else '移到回收站'}
                try:
                    if not within(snapshot.path, candidate.path):
                        raise ValueError('文件不属于所选条目')
                    if permanent:
                        delete_permanently(snapshot, roots)
                    else:
                        recycle_file(snapshot, roots)
                    event['result'] = '成功'
                    summary['success'] += 1
                    summary['deleted_bytes' if permanent else 'recycled_bytes'] += snapshot.size
                except (OSError, ValueError, RuntimeError) as exc:
                    event['result'] = str(exc)
                    summary['skipped'] += 1
                    if len(summary['errors']) < 20:
                        summary['errors'].append(f'{snapshot.path}: {exc}')
                log.write(json.dumps(event, ensure_ascii=False) + '\n')
                log.flush()
                if (summary['success'] + summary['skipped']) % 25 == 0:
                    progress(f'已处理 {summary["success"] + summary["skipped"]:,} 个文件；跳过 {summary["skipped"]:,} 个')
    return summary


def export_report(result, path, include_private=False):
    report = {'scanned_at': time.strftime('%Y-%m-%d %H:%M:%S'), 'files_scanned': result.scanned_files,
              'cancelled': result.cancelled, 'skipped_links': result.skipped_links,
              'errors': result.errors, 'items': []}
    for c in result.candidates:
        report['items'].append({'path': c.path, 'name': c.name, 'category': c.category,
                                'bytes': c.total_bytes, 'eligible_bytes': c.eligible_bytes,
                                'files': c.total_files, 'purpose': c.purpose, 'advice': c.advice,
                                'protected': c.protected})
    if not include_private:
        categories = {}
        for candidate in result.candidates:
            label = candidate.category if candidate.category in {
                '缓存', '更新包', '日志/诊断', '系统管理', '保护项', '模型/虚拟磁盘',
                '个人数据', '未完成下载', '安装包/资料', '个人文件', '用途待确认'} else '其他'
            row = categories.setdefault(label, {'bytes': 0, 'eligible_bytes': 0, 'files': 0})
            row['bytes'] += candidate.total_bytes
            row['eligible_bytes'] += candidate.eligible_bytes
            row['files'] += candidate.total_files
        report = {'privacy': 'summary', 'files_scanned': result.scanned_files,
                  'cancelled': result.cancelled, 'skipped_links': result.skipped_links,
                  'error_count': len(result.errors), 'categories': categories}
    else:
        report['privacy'] = 'private-paths'
    Path(path).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')

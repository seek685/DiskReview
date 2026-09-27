"""Application storage discovery from known paths and Windows uninstall metadata."""
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import stat
import threading
import time

from core import REPARSE, key, plain_path, sensitive_path, within
from platform_paths import system_directories, user_directories
from windows_ops import process_inventory, recycle_path, stop_confirmed_processes

CACHE_NAMES = {'cache', 'cache_data', 'code cache', 'gpucache', 'dawncache', 'shadercache',
               'cachestorage', 'cachedextensionvsixs', 'crx_cache', 'npm-cache', 'staging',
               'updates_v2', 'obsidian-updater', 'updater', 'update_downloading', 'd3dscache'}
DATA_WARNING = '包含配置、账号状态、数据库或离线资料；整目录回收会重置对应本地数据，可能需要重新登录。'
PROGRAM_KINDS = {'程序', '程序/数据混合'}


@dataclass
class Location:
    app: str
    path: str
    kind: str
    purpose: str
    aliases: list = field(default_factory=list)
    parent_path: str = ''
    total_bytes: int = 0
    total_files: int = 0
    latest: float = 0
    issues: list = field(default_factory=list)
    root_identity: tuple = ()
    recycle_allowed: bool = True

    @property
    def selectable(self):
        return (self.recycle_allowed and self.kind not in PROGRAM_KINDS and not self.issues
                and bool(self.root_identity) and not sensitive_path(self.path))


@dataclass
class Inventory:
    locations: list
    process_roots: dict
    errors: list
    skipped_links: int = 0
    cancelled: bool = False
    seconds: float = 0

    def totals(self):
        totals = {}
        for item in self.locations:
            row = totals.setdefault(item.app, {'total': 0, 'data': 0, 'program': 0, 'cache': 0})
            if not item.parent_path:
                row['total'] += item.total_bytes
                row['program' if item.kind in PROGRAM_KINDS else 'data'] += item.total_bytes
            if item.kind == '缓存':
                row['cache'] += item.total_bytes
        return totals


def installed_locations():
    import winreg
    found = []
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
            try:
                with winreg.OpenKey(hive, r'Software\Microsoft\Windows\CurrentVersion\Uninstall', 0,
                                    winreg.KEY_READ | view) as root:
                    for index in range(winreg.QueryInfoKey(root)[0]):
                        try:
                            with winreg.OpenKey(root, winreg.EnumKey(root, index)) as app:
                                name = winreg.QueryValueEx(app, 'DisplayName')[0]
                                try:
                                    path = winreg.QueryValueEx(app, 'InstallLocation')[0]
                                except OSError:
                                    path = ''
                                if path and name:
                                    found.append((str(name), os.path.expandvars(str(path).strip('"'))))
                        except OSError:
                            pass
            except OSError:
                pass
    return found


def app_name(name):
    lower = name.casefold()
    mappings = (
        (('微信', 'weixin', 'wechat', 'xwechat'), '微信'), (('飞书', 'feishu', 'larkshell', 'lark'), '飞书'),
        (('chrome', 'google chrome'), 'Chrome'), (('edge',), 'Microsoft Edge'),
        (('visual studio code', 'vscode', 'code'), 'VS Code'), (('codex', 'openai'), 'Codex'),
        (('wps', 'kingsoft'), 'WPS'), (('lceda', 'jlc-assistant', '嘉立创'), '嘉立创 EDA'),
        (('ollama',), 'Ollama'), (('bilibili', '哔哩'), '哔哩哔哩'), (('baidu', '百度'), '百度网盘'),
        (('obsidian',), 'Obsidian'), (('arduino',), 'Arduino / ESP32'), (('stm32',), 'STM32Cube'),
        (('vivado', 'vitis', 'xilinx'), 'Vivado / Vitis'), (('quartus',), 'Quartus'),
        (('modelsim',), 'ModelSim'), (('antigravity',), 'Antigravity'),
        (('tencent qq', 'qq'), 'QQ'), (('wemeet', '腾讯会议'), '腾讯会议'),
        (('androws', '应用宝'), '腾讯应用宝 / Androws'), (('netease', 'cloudmusic', '网易云'), '网易云音乐'),
        (('doubao', '豆包'), '豆包'), (('quark', '夸克'), '夸克'), (('ima.copilot',), 'ima'),
        (('labcenter', 'proteus'), 'Proteus'), (('sogou', '搜狗'), '搜狗'),
        (('rt-thread',), 'RT-Thread'), (('mounriver',), 'MounRiver Studio'),
    )
    for fragments, owner in mappings:
        if any(lower == text or lower.startswith(text + ' ') or text in lower for text in fragments if len(text) > 3):
            return owner
        if lower in fragments:
            return owner
    return name


def discover_locations(user, roots):
    locations, errors = {}, []
    process_roots = {}
    local, roaming, documents = user_directories(user)
    windows, programs, programs_x86, program_data = system_directories()
    def add(owner, path, kind, purpose='', allowed=True):
        allowed = allowed and owner != 'Codex'
        path = os.path.abspath(path)
        if not os.path.isdir(path):
            return
        actual = os.path.realpath(path)
        try:
            plain_path(actual, roots)
        except (OSError, ValueError) as exc:
            errors.append(f'{path}: {exc}')
            return
        # Never offer a disk, profile, broad vendor or Windows folder as one deletable app.
        broad = {key(p) for p in (user, os.path.join(user, 'AppData'), local, roaming,
                                  windows, programs, programs_x86, program_data, documents)}
        if key(actual) in broad:
            return
        item = locations.get(key(actual))
        if item:
            if path not in item.aliases:
                item.aliases.append(path)
            if kind in PROGRAM_KINDS:
                item.kind = kind
            return
        if not purpose:
            purpose = '已安装的软件文件；优先使用系统卸载。' if kind in PROGRAM_KINDS else DATA_WARNING
        locations[key(actual)] = Location(owner, actual, kind, purpose, [path], recycle_allowed=allowed)
        if owner not in ('其他 / 未识别', '共享组件') and allowed:
            process_roots.setdefault(owner, []).append(actual)

    local_specs = (
        ('Google/Chrome/User Data', 'Chrome', '应用数据'), ('Microsoft/Edge/User Data', 'Microsoft Edge', '应用数据'),
        ('Microsoft/vscode-cpptools', 'VS Code', '缓存'), ('Feishu', '飞书', '程序/数据混合'),
        ('Kingsoft', 'WPS', '程序/数据混合'), ('Ollama', 'Ollama', '应用数据'),
        ('LCEDA-Pro', '嘉立创 EDA', '应用数据'), ('obsidian-updater', 'Obsidian', '缓存'),
        ('Arduino15', 'Arduino / ESP32', '工具链/资源'), ('stm32cube', 'STM32Cube', '应用数据'),
        ('OpenAI/Codex', 'Codex', '程序/数据混合'), ('Doubao', '豆包', '程序/数据混合'),
        ('ima.copilot', 'ima', '程序/数据混合'), ('Quark', '夸克', '程序/数据混合'),
        ('Netease', '网易云音乐', '应用数据'), ('npm-cache', 'npm', '缓存'), ('pip/cache', 'Python pip', '缓存'),
    )
    roaming_specs = (
        ('Tencent/xwechat', '微信'), ('Tencent/WeChat', '微信'), ('Tencent/QQ', 'QQ'),
        ('Tencent/WeMeet', '腾讯会议'), ('WeMeetApp', '腾讯会议'), ('Code', 'VS Code'),
        ('LarkShell', '飞书'), ('kingsoft', 'WPS'), ('bilibili', '哔哩哔哩'),
        ('jlc-assistant', '嘉立创 EDA'), ('obsidian', 'Obsidian'), ('BaiduNetdisk', '百度网盘'),
        ('BaiduYunGuanjia', '百度网盘'), ('Antigravity', 'Antigravity'), ('Antigravity IDE', 'Antigravity'),
        ('Labcenter Electronics', 'Proteus'), ('npm', 'npm'), ('SogouPy', '搜狗'),
    )
    for base in (local,):
        for suffix, owner, kind in local_specs:
            add(owner, os.path.join(base, *suffix.split('/')), kind)
    for base in (roaming,):
        for suffix, owner in roaming_specs:
            add(owner, os.path.join(base, *suffix.split('/')), '应用数据')
    extras = (
        ('微信', os.path.join(documents, 'xwechat_files'), '聊天资料', '微信聊天数据库、图片、视频、附件与备份。整目录回收将移走这些本地资料。'),
        ('微信', os.path.join(documents, 'WeChat Files'), '聊天资料', '旧版微信本地聊天记录、附件及备份。'),
        ('QQ', os.path.join(documents, 'Tencent Files'), '聊天资料', 'QQ 本地聊天记录、接收文件和附件。'),
        ('Codex', os.path.join(user, '.codex'), '应用数据', '会话、工作副本、扩展及应用配置。仅统计，不读取配置内容。'),
        ('VS Code', os.path.join(user, '.vscode'), '应用数据', '已安装扩展及相关状态；回收后扩展需要重新安装。'),
        ('Codex', os.path.join(user, '.cache', 'codex-runtimes'), '工具链/资源', '应用的运行环境和依赖，可能正在使用。'),
        ('Ollama', os.path.join(user, '.ollama', 'models'), '模型/资源', '本地 AI 模型；移走后需要重新下载才能使用。'),
    )
    for owner, path, kind, purpose in extras:
        add(owner, path, kind, purpose, allowed=owner != 'Codex')
    if os.environ.get('OLLAMA_MODELS'):
        add('Ollama', os.environ['OLLAMA_MODELS'], '模型/资源')
    # Windows uninstall registry contains app names/installation paths, not app credentials.
    for name, path in installed_locations():
        if os.path.isdir(path):
            actual = os.path.realpath(path)
            if any(within(actual, loc.path) or within(loc.path, actual) for loc in locations.values()):
                continue
            add(app_name(name), path, '程序')
    # Unknown AppData folders remain visible, but not offered for automated shutdown/deletion.
    def add_unknown(base, depth=0):
        try:
            entries = list(os.scandir(base))
        except OSError:
            return
        for entry in entries:
            try:
                if not entry.is_dir():
                    continue
                actual = os.path.realpath(entry.path)
                if any(within(actual, loc.path) for loc in locations.values()):
                    continue
                if any(within(loc.path, actual) for loc in locations.values()):
                    if depth < 2:
                        add_unknown(entry.path, depth + 1)
                    continue
                if entry.name.casefold() in ('temp', 'application data', 'history', 'temporary internet files', 'packages'):
                    continue
                add(app_name(entry.name), entry.path, '未识别应用数据',
                    '按 AppData 目录名称归属，可能含配置、数据或运行组件；未读取内部配置，暂只展示。', False)
            except OSError as exc:
                errors.append(f'{entry.path}: {exc}')
    for base in (local, roaming):
        add_unknown(base)
    package_root = os.path.join(local, 'Packages')
    if os.path.isdir(package_root):
        try:
            for entry in os.scandir(package_root):
                if entry.is_dir():
                    add(app_name(entry.name.split('_')[0]), entry.path, '应用包数据',
                        'Microsoft Store 应用的本地数据与缓存；可能包含隔离应用状态。使用 Windows 应用设置管理。', False)
        except OSError as exc:
            errors.append(f'{package_root}: {exc}')
    # Only outer roots are walked; inner paths become cache subrows during traversal.
    ordered = sorted(locations.values(), key=lambda item: len(item.path))
    outer = []
    for loc in ordered:
        if not any(within(loc.path, parent.path) for parent in outer):
            outer.append(loc)
    return outer, process_roots, errors


def measure(location, roots, progress=lambda _: None, cancel=None, include_caches=True):
    cancel = cancel or threading.Event()
    plain_path(location.path, roots)
    root_info = os.stat(location.path, follow_symlinks=False)
    location.root_identity = (root_info.st_dev, root_info.st_ino)
    caches = {}
    stack = [(location.path, None)]
    last = 0
    while stack and not cancel.is_set():
        folder, cache = stack.pop()
        try:
            with os.scandir(folder) as entries:
                for entry in entries:
                    if cancel.is_set():
                        break
                    try:
                        info = entry.stat(follow_symlinks=False)
                        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & REPARSE:
                            location.issues.append(f'跳过链接/云占位符：{entry.path}')
                            if cache:
                                cache.issues.append(f'链接：{entry.path}')
                            continue
                        if sensitive_path(entry.path):
                            location.issues.append(f'受保护的凭据或工具文件：{entry.path}')
                            if cache:
                                cache.issues.append(f'受保护文件：{entry.path}')
                            if entry.is_dir(follow_symlinks=False):
                                continue
                        if entry.is_dir(follow_symlinks=False):
                            child_cache = cache
                            if include_caches and not cache and location.kind != '缓存' and entry.name.casefold() in CACHE_NAMES:
                                child_cache = Location(location.app, entry.path, '缓存', '应用缓存或下载暂存；使用软件时可能重新生成。',
                                                       parent_path=location.path,
                                                       recycle_allowed=location.recycle_allowed and location.kind not in (
                                                           '程序', '下载资料', '工具链/资源', '模型/资源'))
                                child_info = os.stat(entry.path, follow_symlinks=False)
                                child_cache.root_identity = (child_info.st_dev, child_info.st_ino)
                                caches[entry.path] = child_cache
                            stack.append((entry.path, child_cache))
                        else:
                            for target in (location, cache) if cache else (location,):
                                target.total_bytes += info.st_size
                                target.total_files += 1
                                target.latest = max(target.latest, info.st_mtime)
                    except OSError as exc:
                        location.issues.append(f'{entry.path}: {exc}')
                        if cache:
                            cache.issues.append(str(exc))
                    if time.monotonic() - last > 0.5:
                        progress(f'正在统计 {location.app} · {location.total_files:,} 个文件 · {folder}')
                        last = time.monotonic()
        except OSError as exc:
            location.issues.append(f'{folder}: {exc}')
            if cache:
                cache.issues.append(str(exc))
    if cancel.is_set():
        location.issues.append('扫描已停止，大小不完整')
        for cache in caches.values():
            cache.issues.append('扫描未完成')
    return list(caches.values())


def scan_apps(user, roots, progress=lambda _: None, cancel=None, locations=None):
    started = time.monotonic()
    cancel = cancel or threading.Event()
    if locations is None:
        locations, process_roots, errors = discover_locations(user, roots)
    else:
        process_roots, errors = {}, []
    output = []
    for location in locations:
        if cancel.is_set():
            break
        try:
            caches = measure(location, roots, progress, cancel)
            output.append(location)
            output.extend(caches)
            errors.extend(location.issues)
        except (OSError, ValueError) as exc:
            location.issues.append(str(exc))
            errors.append(f'{location.path}: {exc}')
            output.append(location)
    return Inventory(output, process_roots, errors, sum('链接' in e for e in errors),
                     cancel.is_set(), time.monotonic() - started)


def selected_roots(items):
    output = []
    for item in sorted(items, key=lambda x: len(x.path)):
        if not any(within(item.path, parent.path) for parent in output):
            output.append(item)
    return output


def related_processes(items, inventory, processes=None):
    owners = {item.app for item in items}
    app_roots = [path for owner in owners for path in inventory.process_roots.get(owner, [])]
    excluded = {'explorer.exe', 'svchost.exe', 'services.exe', 'lsass.exe', 'wininit.exe', 'csrss.exe',
                'system', 'winlogon.exe', 'dwm.exe', 'securityhealthservice.exe', 'msmpeng.exe'}
    matches = []
    for process in process_inventory() if processes is None else processes:
        if process.pid == os.getpid() or process.name.casefold() in excluded:
            continue
        if within(process.path, system_directories()[0]):
            continue
        if any(within(process.path, root) for root in app_roots):
            matches.append(process)
    return matches


def recycle_locations(items, roots, confirmed_processes, log_path, force=False,
                      progress=lambda _: None, cancel=None):
    cancel = cancel or threading.Event()
    items = selected_roots(items)
    for item in items:
        if not item.selectable:
            raise ValueError(f'目录不允许直接回收或扫描不完整：{item.path}')
        plain_path(item.path, roots)
    result = {'success': 0, 'skipped': 0, 'recycled_bytes': 0, 'errors': [], 'stopped': [], 'cancelled': False}
    with open(log_path, 'a', encoding='utf-8') as log:
        def write(event):
            log.write(json.dumps({'time': time.strftime('%Y-%m-%d %H:%M:%S'), **event}, ensure_ascii=False) + '\n')
            log.flush()
        if cancel.is_set():
            result['cancelled'] = True
            return result
        if force:
            write({'action': '用户确认关闭进程', 'processes': [p.__dict__ for p in confirmed_processes]})
            try:
                result['stopped'] = stop_confirmed_processes(confirmed_processes, cancel)
            except Exception as exc:
                write({'action': '进程退出失败', 'error': str(exc)})
                raise
            write({'action': '进程退出结果', 'processes': result['stopped']})
        for item in items:
            if cancel.is_set():
                result['cancelled'] = True
                break
            progress(f'复核并移到回收站：{item.app} · {item.path}')
            event = {'action': '整目录移到回收站', 'path': item.path, 'app': item.app}
            try:
                plain_path(item.path, roots)
                current = os.stat(item.path, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != item.root_identity:
                    raise ValueError('目录已被替换，请重新扫描')
                fresh = Location(item.app, item.path, item.kind, item.purpose)
                measure(fresh, roots, progress, cancel, include_caches=False)
                if fresh.issues:
                    raise ValueError('目录包含链接、无法读取项目或扫描被停止，整目录回收已跳过')
                if cancel.is_set():
                    result['cancelled'] = True
                    break
                recycle_path(item.path)
                result['success'] += 1
                result['recycled_bytes'] += fresh.total_bytes
                event.update(result='成功', bytes=fresh.total_bytes)
            except (OSError, RuntimeError, ValueError) as exc:
                result['skipped'] += 1
                result['errors'].append(f'{item.path}: {exc}')
                event['result'] = str(exc)
            write(event)
    return result


def export_inventory(inventory, path, include_private=False):
    report = {'scanned_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'totals': inventory.totals(), 'locations': [item.__dict__ for item in inventory.locations],
        'errors': inventory.errors, 'cancelled': inventory.cancelled, 'seconds': inventory.seconds}
    if not include_private:
        categories = {}
        for item in inventory.locations:
            label = item.kind if item.kind in {
                '程序', '程序/数据混合', '应用数据', '缓存', '聊天资料', '笔记库',
                '工具链/资源', '模型/资源', '下载资料', '未识别应用数据', '应用包数据'} else '其他'
            row = categories.setdefault(label, {'bytes': 0, 'files': 0, 'locations': 0})
            row['bytes'] += item.total_bytes
            row['files'] += item.total_files
            row['locations'] += 1
        report = {'privacy': 'summary', 'categories': categories,
                  'error_count': len(inventory.errors), 'cancelled': inventory.cancelled,
                  'cache_included_in_parent_totals': True}
    else:
        report['privacy'] = 'private-paths'
    Path(path).write_text(json.dumps(report,
        ensure_ascii=False, indent=2), encoding='utf-8')

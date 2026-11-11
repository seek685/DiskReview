"""Read-only directory accounting and conservative explanations for the system drive."""
from dataclasses import dataclass, field
import os
import shutil
import stat
import threading
import time

from core import MIB, REPARSE, cache_rules, key, plain_path, sensitive_path, within
from platform_paths import system_directories, user_directories


def system_drive():
    return os.path.abspath(os.environ.get('SystemDrive', 'C:') + '\\')


@dataclass
class Usage:
    path: str
    parent: str = ''
    size: int = 0
    files: int = 0
    errors: int = 0
    links: int = 0
    directory: bool = True


@dataclass
class Audit:
    root: str
    nodes: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)
    cancelled: bool = False
    seconds: float = 0
    total: int = 0
    free: int = 0

    def children(self, path):
        return sorted((n for n in self.nodes.values() if n.parent == key(path)),
                      key=lambda n: n.size, reverse=True)


def audit_drive(root, progress=lambda _: None, cancel=None, large_file=100 * MIB):
    """Visit each directory once. Never traverse junctions, links or cloud placeholders."""
    root = os.path.abspath(root)
    # Validate the root and every ancestor, even when called directly from the CLI.
    if root.startswith(('\\\\', '//')):
        raise ValueError('仅扫描本地磁盘，不扫描网络路径。')
    if os.path.dirname(root) != root:
        plain_path(root, [os.path.dirname(root)])
    info = os.lstat(root)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & REPARSE:
        raise ValueError('扫描根目录必须是本地普通目录，不能是链接。')
    cancel = cancel or threading.Event()
    result = Audit(root)
    try:
        disk = shutil.disk_usage(root)
        result.total, result.free = disk.total, disk.free
    except OSError:
        pass
    started, last = time.monotonic(), 0
    result.nodes[key(root)] = Usage(root)
    stack = [root]
    count = 0
    while stack and not cancel.is_set():
        folder = stack.pop()
        node = result.nodes[key(folder)]
        try:
            with os.scandir(folder) as entries:
                for entry in entries:
                    if cancel.is_set():
                        break
                    try:
                        data = entry.stat(follow_symlinks=False)
                        if stat.S_ISLNK(data.st_mode) or getattr(data, 'st_file_attributes', 0) & REPARSE:
                            node.links += 1
                            continue
                        if stat.S_ISDIR(data.st_mode):
                            result.nodes[key(entry.path)] = Usage(entry.path, key(folder))
                            stack.append(entry.path)
                        elif stat.S_ISREG(data.st_mode):
                            node.size += data.st_size
                            node.files += 1
                            count += 1
                            if data.st_size >= large_file:
                                result.nodes[key(entry.path)] = Usage(entry.path, key(folder), data.st_size, 1, directory=False)
                    except OSError as exc:
                        node.errors += 1
                        if len(result.errors) < 100:
                            result.errors.append(f'{entry.path}: {exc}')
                    if time.monotonic() - last > 0.5:
                        progress(f'已检查 {count:,} 个文件 · {folder}')
                        last = time.monotonic()
        except OSError as exc:
            node.errors += 1
            if len(result.errors) < 100:
                result.errors.append(f'{folder}: {exc}')
    # Insertion order puts parents before descendants. Files already belong to a directory.
    for node in reversed(list(result.nodes.values())):
        if node.parent and node.directory:
            parent = result.nodes[node.parent]
            parent.size += node.size
            parent.files += node.files
            parent.errors += node.errors
            parent.links += node.links
    result.cancelled = cancel.is_set()
    result.seconds = time.monotonic() - started
    return result


def explain(path, user, rules=None):
    """Return decision, reason, next action. Only explicit cache rules are reusable data."""
    path = os.path.abspath(path)
    parts = path.replace('\\', '/').casefold().split('/')
    name = parts[-1]
    windows, programs, programs_x86, programdata = system_directories()
    if sensitive_path(path):
        if '.codex' in parts:
            return ('保护 / 不直接删', 'Codex 配置、账号、会话和插件资料混合存放，不能整目录当缓存清理。',
                    '展开查看占用；保留账号和会话资料，通过所属工具管理。')
        return ('保护 / 不直接删', '凭据、工程版本历史或工具自身资料。', '保留；通过所属软件管理。')
    if name in ('pagefile.sys', 'swapfile.sys', 'hiberfil.sys'):
        purposes = {'pagefile.sys': '虚拟内存分页文件', 'swapfile.sys': 'Windows 交换文件', 'hiberfil.sys': '休眠和快速启动文件'}
        return ('系统管理', purposes[name] + '，不是普通垃圾。', '不要手删；需要调整时使用 Windows 系统设置。')
    for rule in sorted(rules if rules is not None else cache_rules(user), key=lambda r: len(r.path), reverse=True):
        if within(path, rule.path):
            return ('系统管理' if rule.managed else '可清理缓存' if rule.category == '缓存' else '确认后清理',
                    rule.purpose, rule.advice)
    if '$recycle.bin' in parts:
        return ('确认后清理', '回收站内的文件仍占空间。', '在回收站核对并恢复需要的文件，再手动清空；清空后无法从回收站恢复。')
    if within(path, windows) or 'system volume information' in parts or name in ('$extend', '$mft', '$logfile', 'recovery', '$winreagent'):
        return ('系统管理', 'Windows、安装维护、恢复或还原数据。', '使用“系统临时文件”或“系统磁盘清理”；WinSxS 和 Installer 不可手动删除。')
    if 'windows.old' in parts or '$windows.~bt' in parts or '$windows.~ws' in parts:
        return ('系统管理', '旧系统或系统升级资料；删除可能失去版本回退能力。', '确认不再回退后，在“系统临时文件”中处理。')
    if any(within(path, base) for base in (programs, programs_x86, os.path.join(user, 'AppData', 'Local', 'Programs'))) or 'codex-runtimes' in parts:
        return ('卸载 / 不手删', '已安装软件及其运行组件。', '使用“已安装应用”卸载不用的软件；支持迁移的应用可迁到 D 盘。')
    if '.vscode' in parts and 'extensions' in parts:
        return ('卸载 / 不手删', '已安装的 VS Code 扩展和扩展运行组件，不是下载缓存。',
                '在 VS Code 的扩展页面卸载不用的扩展。')
    if within(path, programdata):
        return ('需确认资料', '所有用户共享的应用数据，可能含数据库、授权和安装维护资料。', '先看具体子目录，在所属软件中清理；不要整目录删除。')
    if any(p in parts for p in ('xwechat_files', 'wechat files', 'weixin', 'xwechat')):
        return ('需确认资料', '微信聊天数据、图片、视频或附件，可能无法重新下载。', '先备份聊天记录，在微信“设置 → 存储空间”中管理或迁移。')
    if name.endswith(('.vhd', '.vhdx', '.vmdk', '.gguf', '.safetensors')) or any(p in parts for p in ('.ollama', 'huggingface', 'ollamamodels', 'docker')):
        return ('需确认资料', '模型、容器或虚拟磁盘，可能包含正在使用的模型、系统和工程。', '通过对应软件删除不用的模型、镜像或迁移；不要按缓存整目录删除。')
    if name in ('downloads', 'desktop', 'documents', 'pictures', 'videos', 'music'):
        return ('需确认资料', '下载、桌面、文档或媒体等个人资料。', '核对后移动到 D 盘；安装包可能可以删除，工程和唯一备份请保留。')
    local, roaming, _ = user_directories(user)
    if any(within(path, base) for base in (local, roaming, os.path.join(user, 'AppData'))):
        return ('需确认资料', '应用设置、账号资料、数据库和缓存混合存放。', '展开子目录查看；只清理明确识别的缓存，勿整删 AppData 或应用配置目录。')
    if any(p in parts for p in ('.cache', 'cache', 'node_modules', '.vscode', '.conda', '.nuget', '.gradle', '.cargo', '.rustup')):
        return ('需确认资料', '可能混有模型、依赖、扩展或工具链，目录名不能证明可删。', '先确认用途；使用对应开发工具管理，离线依赖和工程需要保留。')
    return ('需确认用途', '未识别为可再生成的缓存，大小本身不能证明无用。', '展开或打开位置核对；不确定时保留。')


def recommendations(result, user, rules=None):
    """Non-overlapping actionable locations; parent and child are never added together."""
    rules = cache_rules(user) if rules is None else rules
    rows = []
    paths = {key(r.path) for r in rules}
    paths.add(key(os.path.join(result.root, '$Recycle.Bin')))
    for node in sorted((n for k, n in result.nodes.items() if k in paths), key=lambda n: len(n.path)):
        if not node.size or node.errors or result.cancelled:
            continue
        decision = explain(node.path, user, rules)[0]
        if decision not in ('可清理缓存', '确认后清理'):
            continue
        if any(within(node.path, old.path) for old in rows):
            continue
        rows.append(node)
    return sorted(rows, key=lambda n: n.size, reverse=True)

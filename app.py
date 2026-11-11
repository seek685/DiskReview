import argparse
import ctypes
from datetime import datetime
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from core import GIB, MIB, cache_rules, clean, export_report, format_size, scan
from platform_paths import fixed_drives, report_directory

APP_DIR = Path(__file__).resolve().parent
USER_DIR = Path(os.environ.get('USERPROFILE', str(Path.home())))
ROOTS = fixed_drives()
REPORT_DIR = report_directory()
MODE_TEXT = {
    '推荐方式': '缓存和更新包确认后永久清理；普通文件、安装包、日志和诊断文件移到回收站。',
    '全部回收站': '所有选中文件移到回收站；清空回收站后才释放空间。',
    '永久删除': '所有选中文件永久删除，不经过回收站，不能从回收站恢复。',
}


class App:
    def __init__(self, root):
        self.root = root
        self.root.title('磁盘清理助手 · 本地扫描 / 自己选择')
        width = min(1320, self.root.winfo_screenwidth() - 60)
        height = min(860, self.root.winfo_screenheight() - 100)
        self.root.geometry(f'{width}x{height}+20+20')
        self.root.minsize(min(1000, width), min(620, height))
        self.events = queue.Queue()
        self.cancel = threading.Event()
        self.busy = False
        self.result = None
        self.selected = set()
        self.stale = False
        self.filter_timer = None
        self.search = tk.StringVar()
        self.category = tk.StringVar(value='全部项目')
        self.days = tk.StringVar(value='7')
        self.cache_mb = tk.StringVar(value='100')
        self.file_mb = tk.StringVar(value='500')
        self.mode = tk.StringVar(value='全部回收站')
        self.space = tk.StringVar()
        self.status = tk.StringVar(value='尚未扫描。所有项目默认不勾选。')
        self.selection_text = tk.StringVar(value='已勾选 0 项')
        self.mode_hint = tk.StringVar(value=MODE_TEXT[self.mode.get()])
        self._build()
        self.refresh_space()
        self.root.after(100, self.poll)
        self.root.protocol('WM_DELETE_WINDOW', self.close)

    def _build(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('.', font=('Microsoft YaHei UI', 10))
        style.configure('TFrame', background='#f5f7fb')
        style.configure('TLabel', background='#f5f7fb', foreground='#172b4d')
        style.configure('Title.TLabel', font=('Microsoft YaHei UI', 23, 'bold'))
        style.configure('Muted.TLabel', foreground='#53657f')
        style.configure('TButton', padding=(12, 7))
        style.configure('Accent.TButton', background='#1764df', foreground='white')
        style.map('Accent.TButton', background=[('active', '#0d4eb9')])
        style.configure('Treeview', rowheight=34, background='white', fieldbackground='white')
        style.configure('Treeview.Heading', font=('Microsoft YaHei UI', 10, 'bold'), padding=8)
        outer = ttk.Frame(self.root, padding=22)
        outer.pack(fill='both', expand=True)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(7, weight=1)
        header = ttk.Frame(outer)
        header.grid(row=0, column=0, sticky='ew')
        ttk.Label(header, text='磁盘清理助手', style='Title.TLabel').pack(side='left')
        ttk.Label(header, textvariable=self.space, style='Muted.TLabel').pack(side='right')
        ttk.Label(outer, text='本机扫描，不上传文件。看清用途 → 勾选项目 → 确认清理。系统、聊天数据库、模型和软件本体受到保护。',
                  style='Muted.TLabel', wraplength=1000).grid(row=1, column=0, sticky='w', pady=(8, 12))
        controls = ttk.Frame(outer)
        controls.grid(row=2, column=0, sticky='ew')
        self.c_button = ttk.Button(controls, text='C 盘空间诊断', style='Accent.TButton', command=self.open_c_audit)
        self.c_button.pack(side='left', padx=(0, 8))
        self.quick = ttk.Button(controls, text='快速扫描缓存', style='Accent.TButton', command=lambda: self.start_scan(False))
        self.quick.pack(side='left', padx=(0, 8))
        self.full = ttk.Button(controls, text='扫描本地磁盘', command=lambda: self.start_scan(True))
        self.full.pack(side='left', padx=(0, 8))
        self.apps_button = ttk.Button(controls, text='应用数据 / 占用', command=self.open_apps)
        self.apps_button.pack(side='left', padx=(0, 8))
        self.cancel_button = ttk.Button(controls, text='停止', state='disabled', command=self.cancel.set)
        self.cancel_button.pack(side='left')
        ttk.Button(controls, text='Windows 存储设置', command=self.open_storage).pack(side='right')
        action = ttk.Frame(outer)
        action.grid(row=3, column=0, sticky='ew', pady=(12, 5))
        action.columnconfigure(0, weight=1)
        ttk.Label(action, textvariable=self.selection_text, font=('Microsoft YaHei UI', 11, 'bold'),
                  wraplength=280).grid(row=0, column=0, sticky='w')
        self.mode_combo = ttk.Combobox(action, textvariable=self.mode, values=tuple(MODE_TEXT), state='readonly', width=12)
        self.mode_combo.grid(row=0, column=1, padx=8)
        self.mode_combo.bind('<<ComboboxSelected>>', lambda _: self.mode_hint.set(MODE_TEXT[self.mode.get()]))
        self.export_button = ttk.Button(action, text='导出清单', command=self.export, state='disabled')
        self.export_button.grid(row=0, column=2, padx=(0, 8))
        self.clean_button = ttk.Button(action, text='清理 / 删除勾选项…', style='Accent.TButton', state='disabled', command=self.start_cleanup)
        self.clean_button.grid(row=0, column=3, sticky='e')
        ttk.Label(outer, textvariable=self.mode_hint, style='Muted.TLabel', wraplength=1000).grid(
            row=4, column=0, sticky='w', pady=(3, 8))
        settings = ttk.Frame(outer)
        settings.grid(row=5, column=0, sticky='ew', pady=(4, 8))
        for label, variable, values in (
            ('缓存目录 ≥', self.cache_mb, (10, 50, 100, 200, 500)),
            ('大文件 ≥', self.file_mb, (100, 200, 500, 1000, 2000)),
            ('保留最近', self.days, (0, 3, 7, 14, 30, 90))):
            ttk.Label(settings, text=label).pack(side='left', padx=(0, 5))
            ttk.Spinbox(settings, textvariable=variable, values=values, width=6).pack(side='left')
            ttk.Label(settings, text='天文件' if variable is self.days else 'MB').pack(side='left', padx=(5, 18))
        ttk.Label(settings, text='参数在下次扫描时生效；大文件只在全盘扫描中查找。', style='Muted.TLabel').pack(side='left')
        filters = ttk.Frame(outer)
        filters.grid(row=6, column=0, sticky='ew', pady=(0, 10))
        ttk.Label(filters, text='搜索').pack(side='left', padx=(0, 8))
        ttk.Entry(filters, textvariable=self.search, width=30).pack(side='left', padx=(0, 10))
        combo = ttk.Combobox(filters, textvariable=self.category, state='readonly', width=15,
                             values=('全部项目', '可勾选项目', '缓存/更新/日志', '安装包/个人文件', '保护/系统项目', '已勾选'))
        combo.pack(side='left')
        combo.bind('<<ComboboxSelected>>', lambda _: self.render())
        ttk.Button(filters, text='勾选显示的缓存', command=self.select_visible_caches).pack(side='right')
        ttk.Button(filters, text='取消全部勾选', command=self.clear_selection).pack(side='right', padx=8)
        self.search.trace_add('write', self.search_changed)
        frame = ttk.Frame(outer)
        frame.grid(row=7, column=0, sticky='nsew')
        columns = ('check', 'category', 'name', 'size', 'eligible', 'advice', 'path')
        self.tree = ttk.Treeview(frame, columns=columns, show='headings', selectmode='browse', height=4)
        labels = ('勾选', '类型', '项目', '总大小', '可处理', '建议', '路径')
        widths = (48, 105, 195, 90, 90, 250, 360)
        for col, label, width in zip(columns, labels, widths):
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, minwidth=width if col in ('check', 'size', 'eligible') else 90,
                             stretch=col in ('name', 'advice', 'path'))
        vertical = ttk.Scrollbar(frame, orient='vertical', command=self.tree.yview)
        horizontal = ttk.Scrollbar(frame, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        vertical.grid(row=0, column=1, sticky='ns')
        horizontal.grid(row=1, column=0, sticky='ew')
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self.tree.tag_configure('protected', foreground='#768096')
        self.tree.tag_configure('selected', background='#e8f0ff')
        self.tree.bind('<Button-1>', self.click)
        self.tree.bind('<space>', self.toggle_keyboard)
        self.tree.bind('<<TreeviewSelect>>', self.show_detail)
        detail_header = ttk.Frame(outer)
        detail_header.grid(row=8, column=0, sticky='ew', pady=(8, 3))
        ttk.Label(detail_header, text='选中一行，查看用途和影响').pack(side='left')
        ttk.Button(detail_header, text='在资源管理器中查看', command=self.reveal).pack(side='right')
        detail_frame = ttk.Frame(outer)
        detail_frame.grid(row=9, column=0, sticky='ew')
        detail_frame.columnconfigure(0, weight=1)
        self.detail = tk.Text(detail_frame, height=3, wrap='word', font=('Microsoft YaHei UI', 10),
                              background='white', foreground='#172b4d', relief='flat', padx=10, pady=8)
        self.detail.grid(row=0, column=0, sticky='ew')
        detail_scroll = ttk.Scrollbar(detail_frame, orient='vertical', command=self.detail.yview)
        detail_scroll.grid(row=0, column=1, sticky='ns')
        self.detail.configure(yscrollcommand=detail_scroll.set)
        self.detail.configure(state='disabled')
        self.progress = ttk.Progressbar(outer, mode='indeterminate')
        self.progress.grid(row=10, column=0, sticky='ew', pady=(8, 0))
        ttk.Label(outer, textvariable=self.status, style='Muted.TLabel', wraplength=1000).grid(
            row=11, column=0, sticky='w', pady=(7, 0))

    def search_changed(self, *_):
        if self.filter_timer:
            self.root.after_cancel(self.filter_timer)
        self.filter_timer = self.root.after(180, self.render)

    def refresh_space(self):
        parts = []
        for drive in ROOTS:
            try:
                usage = shutil.disk_usage(drive)
                parts.append(f'{drive[:2]} 可用 {format_size(usage.free)} / {format_size(usage.total)}')
            except OSError:
                pass
        self.space.set('     '.join(parts))

    def set_busy(self, value):
        self.busy = value
        for button in (self.quick, self.full):
            button.configure(state='disabled' if value else 'normal')
        self.cancel_button.configure(state='normal' if value else 'disabled')
        if value:
            self.progress.start(12)
        else:
            self.progress.stop()
        self.update_selection()

    def start_scan(self, full, roots=None):
        if self.busy:
            return
        try:
            cache_mb, file_mb, days = int(self.cache_mb.get()), int(self.file_mb.get()), int(self.days.get())
            if not 1 <= cache_mb <= 100000 or not 1 <= file_mb <= 100000 or not 0 <= days <= 36500:
                raise ValueError()
        except ValueError:
            messagebox.showerror('检查参数', '大小请输入 1～100000 MB；保留天数请输入 0～36500。', parent=self.root)
            return
        self.result = None
        self.stale = False
        self.selected.clear()
        self.render()
        self.cancel.clear()
        self.set_busy(True)
        self.export_button.configure(state='disabled')
        self.status.set('正在全盘扫描，仅读取文件元数据…' if full else '正在扫描常见缓存目录…')
        def worker():
            try:
                result = scan(roots or ROOTS, cache_rules(str(USER_DIR)), full, cache_mb * MIB, file_mb * MIB, days,
                              lambda text: self.events.put(('progress', text)), self.cancel)
                self.events.put(('scan', result))
            except Exception as exc:
                self.events.put(('error', str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def visible(self, candidate, index):
        needle = self.search.get().casefold().strip()
        if needle and needle not in ' '.join((candidate.name, candidate.path, candidate.purpose, candidate.advice)).casefold():
            return False
        category = self.category.get()
        if category == '可勾选项目':
            return candidate.selectable
        if category == '缓存/更新/日志':
            return candidate.category in ('缓存', '更新包', '日志/诊断')
        if category == '安装包/个人文件':
            return candidate.category in ('安装包/资料', '个人文件', '未完成下载')
        if category == '保护/系统项目':
            return candidate.protected
        if category == '已勾选':
            return index in self.selected
        return True

    def render(self):
        self.filter_timer = None
        current = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        if self.result:
            for index, c in enumerate(self.result.candidates):
                if not self.visible(c, index):
                    continue
                check = '☑' if index in self.selected else '☐' if c.selectable and not self.stale else '—'
                advice = c.advice if c.selectable or c.protected else '保留期内暂无可处理文件；可调整天数重新扫描。'
                self.tree.insert('', 'end', iid=str(index), values=(check, c.category, c.name, format_size(c.total_bytes),
                                 format_size(c.eligible_bytes), advice, c.path),
                                 tags=('selected',) if index in self.selected else ('protected',) if not c.selectable else ())
        if current and self.tree.exists(current[0]):
            self.tree.selection_set(current[0])
        self.update_selection()

    def update_selection(self):
        total = sum(self.result.candidates[i].eligible_bytes for i in self.selected) if self.result else 0
        self.selection_text.set(f'已勾选 {len(self.selected)} 项 · 可处理 {format_size(total)}')
        self.clean_button.configure(state='normal' if self.selected and not self.busy and not self.stale else 'disabled')

    def toggle(self, item):
        if self.busy or self.stale or not self.result or not item:
            return
        index = int(item)
        if not self.result.candidates[index].selectable:
            self.tree.selection_set(item)
            self.show_detail()
            return
        if index in self.selected:
            self.selected.remove(index)
        else:
            self.selected.add(index)
        self.render()

    def click(self, event):
        if self.tree.identify_column(event.x) == '#1':
            self.toggle(self.tree.identify_row(event.y))

    def toggle_keyboard(self, _):
        selected = self.tree.selection()
        if selected:
            self.toggle(selected[0])
        return 'break'

    def select_visible_caches(self):
        if not self.result or self.busy or self.stale:
            return
        for item in self.tree.get_children():
            index = int(item)
            c = self.result.candidates[index]
            if c.selectable and c.category == '缓存':
                self.selected.add(index)
        self.render()

    def clear_selection(self):
        if not self.busy:
            self.selected.clear()
            self.render()

    def show_detail(self, _=None):
        selected = self.tree.selection()
        if not selected or not self.result:
            return
        c = self.result.candidates[int(selected[0])]
        modified = datetime.fromtimestamp(c.latest).strftime('%Y-%m-%d %H:%M') if c.latest else '未知'
        text = (f'{c.path}\n用途：{c.purpose}\n建议：{c.advice}\n'
                f'共 {c.total_files:,} 个文件，{format_size(c.total_bytes)}；满足保留天数的可处理文件 '
                f'{len(c.files):,} 个，{format_size(c.eligible_bytes)}。最近修改：{modified}。'
                '\n大小为逻辑长度；硬链接、压缩和占用文件可能使实际释放空间不同。空目录会保留。')
        self.detail.configure(state='normal')
        self.detail.delete('1.0', 'end')
        self.detail.insert('1.0', text)
        self.detail.configure(state='disabled')

    def reveal(self):
        selected = self.tree.selection()
        if selected and self.result:
            path = self.result.candidates[int(selected[0])].path
            if os.path.exists(path):
                subprocess.Popen(['explorer.exe', '/select,', path])

    def open_storage(self):
        os.startfile('ms-settings:storagesense')

    def open_apps(self):
        from app_view import AppStorageWindow
        existing = getattr(self, 'app_storage', None)
        if existing and existing.window.winfo_exists():
            existing.window.lift()
            return existing
        self.app_storage = AppStorageWindow(self.root, str(USER_DIR), ROOTS, REPORT_DIR)
        return self.app_storage

    def open_c_audit(self):
        from space_view import SpaceWindow
        existing = getattr(self, 'c_audit', None)
        if existing and existing.window.winfo_exists():
            existing.window.lift()
            return existing
        self.c_audit = SpaceWindow(self.root, str(USER_DIR), self.review_c_cache)
        return self.c_audit

    def review_c_cache(self):
        if self.busy:
            messagebox.showinfo('扫描进行中', '请先等待当前操作结束，或点停止。', parent=self.root)
            return False
        from space_audit import system_drive
        self.cache_mb.set('1')
        self.search.set('')
        self.category.set('全部项目')
        self.start_scan(False, roots=[system_drive()])
        return True

    def start_cleanup(self):
        if not self.selected or self.busy or self.stale or not self.result:
            return
        candidates = [self.result.candidates[i] for i in sorted(self.selected)]
        mode = self.mode.get()
        total = sum(c.eligible_bytes for c in candidates)
        names = '\n'.join(f'• {c.name} — {format_size(c.eligible_bytes)}' for c in candidates[:8])
        if len(candidates) > 8:
            names += f'\n…共 {len(candidates)} 项'
        text = (f'将处理 {len(candidates)} 项、约 {format_size(total)}：\n\n{names}\n\n'
                f'{MODE_TEXT[mode]}\n正在占用、已经变化和硬链接文件将跳过。\n\n确认执行？')
        if not messagebox.askyesno('确认清理选中的文件', text, parent=self.root, default='no'):
            return
        self.cancel.clear()
        self.set_busy(True)
        self.status.set('正在处理已勾选的文件…')
        log_dir = REPORT_DIR
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / ('cleanup-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '.jsonl')
        def worker():
            try:
                result = clean(candidates, ROOTS, mode, log_path,
                               lambda text: self.events.put(('progress', text)), self.cancel)
                self.events.put(('clean', (result, log_path)))
            except Exception as exc:
                self.events.put(('error', str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def export(self):
        if not self.result:
            return
        name = filedialog.asksaveasfilename(parent=self.root, title='保存扫描清单', defaultextension='.json',
                                           initialfile='磁盘扫描-' + datetime.now().strftime('%Y%m%d') + '.json',
                                           filetypes=[('JSON 清单', '*.json')])
        if name:
            include_private = messagebox.askyesno('导出隐私选项',
                '是否包含完整路径、文件名和错误详情？这些信息可能暴露账号和个人资料。\n选择“否”导出不含路径和名称的汇总。',
                parent=self.root, default='no')
            export_report(self.result, name, include_private=include_private)
            self.status.set(f'已导出：{name}')

    def poll(self):
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == 'progress':
                    self.status.set(value)
                elif kind == 'scan':
                    self.result = value
                    self.set_busy(False)
                    self.render()
                    self.export_button.configure(state='normal')
                    self.refresh_space()
                    reports = REPORT_DIR
                    reports.mkdir(parents=True, exist_ok=True)
                    export_report(value, reports / 'latest-scan.json', include_private=True)
                    self.status.set(f'{"已停止，展示部分结果" if value.cancelled else "扫描完成"}：'
                                    f'{value.scanned_files:,} 个文件，{len(value.candidates)} 个项目，耗时 {value.seconds:.0f} 秒；'
                                    f'无法读取 {len(value.errors)} 项，跳过链接/云占位符 {value.skipped_links} 项。默认未勾选。')
                elif kind == 'clean':
                    result, log_path = value
                    self.selected.clear()
                    self.stale = True
                    self.set_busy(False)
                    self.render()
                    self.refresh_space()
                    summary = (f'已处理 {result["success"]:,} 个文件；跳过 {result["skipped"]:,} 个。\n'
                               f'永久删除文件合计：{format_size(result["deleted_bytes"])}\n'
                               f'移到回收站：{format_size(result["recycled_bytes"])}（清空回收站才释放空间）\n'
                               f'{"操作已停止，已处理的文件不会自动恢复。" if result["cancelled"] else ""}\n'
                               f'请重新扫描查看剩余项目。日志：{log_path}')
                    self.status.set('本次处理已结束。请重新扫描查看剩余文件；空目录保留，程序运行可能继续生成缓存。')
                    if result['errors']:
                        summary += '\n\n跳过原因示例：\n' + '\n'.join(result['errors'][:3])
                    messagebox.showinfo('清理结果', summary, parent=self.root)
                elif kind == 'error':
                    self.stale = True
                    self.set_busy(False)
                    self.status.set('操作未完成，请重新扫描。')
                    messagebox.showerror('操作未完成', value, parent=self.root)
        except queue.Empty:
            pass
        self.root.after(100, self.poll)

    def close(self):
        c_audit = getattr(self, 'c_audit', None)
        if c_audit and c_audit.window.winfo_exists() and c_audit.busy:
            c_audit.cancel.set()
            self.status.set('正在停止 C 盘分析，结束后可关闭。')
            return
        app_storage = getattr(self, 'app_storage', None)
        if app_storage and app_storage.window.winfo_exists() and app_storage.busy:
            app_storage.cancel.set()
            self.status.set('正在停止应用目录操作，请等待结束后关闭。')
            return
        if self.busy:
            if messagebox.askyesno('停止操作', '操作尚在进行，先停止，再关闭窗口？', parent=self.root):
                self.cancel.set()
                self.status.set('已请求停止，等待当前文件处理结束后可关闭。')
            return
        self.root.destroy()


def main():
    global ROOTS
    parser = argparse.ArgumentParser()
    parser.add_argument('--scan', choices=('quick', 'full', 'apps', 'space'))
    parser.add_argument('--output')
    parser.add_argument('--root', action='append', help='Local directory or drive to scan; repeat for multiple roots')
    parser.add_argument('--include-private-paths', action='store_true', help='Include sensitive paths in exported reports')
    parser.add_argument('--quick-start', action='store_true')
    parser.add_argument('--apps-start', action='store_true')
    parser.add_argument('--c-start', action='store_true', help='Open system-drive analysis on startup')
    args = parser.parse_args()
    if os.name != 'nt':
        parser.error('DiskReview requires Windows 10/11')
    if args.root:
        if any(root.startswith(('\\\\', '//')) or not os.path.isdir(root) for root in args.root):
            parser.error('--root must be an existing local directory or drive')
        ROOTS = [os.path.realpath(root) for root in args.root]
    if args.include_private_paths:
        print('Warning: exported report will contain private file paths and application names.', file=sys.stderr)
    if not args.output:
        output_name = {'apps': 'latest-app-storage.json', 'space': 'latest-space-summary.json'}.get(args.scan, 'latest-scan.json')
        args.output = str(REPORT_DIR / output_name)
    if args.scan:
        if args.scan == 'space':
            from space_audit import audit_drive, system_drive
            result = audit_drive(ROOTS[0] if args.root else system_drive())
            node = result.nodes[os.path.normcase(os.path.abspath(result.root))]
            report = {'total_bytes': result.total, 'free_bytes': result.free, 'logical_bytes': node.size,
                      'files': node.files, 'error_count': node.errors, 'skipped_links': node.links,
                      'cancelled': result.cancelled, 'seconds': round(result.seconds, 1)}
            if args.include_private_paths:
                from dataclasses import asdict
                report['directories_and_large_files'] = [asdict(n) for n in result.nodes.values()]
                report['errors'] = result.errors
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
            print(json.dumps({k: v for k, v in report.items() if k not in ('directories_and_large_files', 'errors')}, ensure_ascii=False))
            return
        if args.scan == 'apps':
            from app_inventory import export_inventory, scan_apps
            result = scan_apps(str(USER_DIR), ROOTS)
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            export_inventory(result, args.output, include_private=args.include_private_paths)
            print(json.dumps({'apps': len(result.totals()), 'locations': len(result.locations),
                              'errors': len(result.errors), 'seconds': round(result.seconds, 1),
                              'output': args.output}, ensure_ascii=False))
            return
        result = scan(ROOTS, cache_rules(str(USER_DIR)), full=args.scan == 'full')
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        export_report(result, args.output, include_private=args.include_private_paths)
        print(json.dumps({'items': len(result.candidates), 'files': result.scanned_files,
                          'errors': len(result.errors), 'seconds': round(result.seconds, 1),
                          'output': args.output}, ensure_ascii=False))
        return
    if os.name == 'nt':
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    root = tk.Tk()
    app = App(root)
    if args.c_start:
        root.after(250, lambda: app.open_c_audit().start_scan())
    if args.quick_start:
        root.after(250, lambda: app.start_scan(False))
    if args.apps_start:
        root.after(250, lambda: app.open_apps().start_scan())
    root.mainloop()


if __name__ == '__main__':
    main()

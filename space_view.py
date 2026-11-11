"""System-drive overview: explanations and size breakdown, without directory deletion."""
import os
import queue
import subprocess
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from core import cache_rules, format_size, key
from space_audit import audit_drive, explain, recommendations, system_drive


class SpaceWindow:
    def __init__(self, parent, user, review_cache, root=None):
        self.user, self.review_cache = user, review_cache
        self.scan_root = root or system_drive()
        self.rules = cache_rules(user)
        self.result = None
        self.busy = False
        self.events = queue.Queue()
        self.cancel = threading.Event()
        self.paths = {}
        self.window = tk.Toplevel(parent)
        self.window.title('C 盘空间诊断 · 看清占用和清理影响')
        self.window.geometry(f'{min(1180, self.window.winfo_screenwidth()-60)}x{min(800, self.window.winfo_screenheight()-100)}+35+35')
        self.window.minsize(940, 620)
        self.status = tk.StringVar(value='点“分析 C 盘”查看大小排行；只读扫描，不会删除文件。')
        self.capacity = tk.StringVar(value='先找占用最大的目录，再按用途决定处理方式。')
        self._build()
        self.timer = self.window.after(100, self.poll)
        self.window.protocol('WM_DELETE_WINDOW', self.close)

    def _build(self):
        outer = ttk.Frame(self.window, padding=16)
        outer.pack(fill='both', expand=True)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(4, weight=1)
        ttk.Label(outer, text='C 盘为什么满？', style='Title.TLabel').grid(row=0, column=0, sticky='w')
        ttk.Label(outer, textvariable=self.capacity, wraplength=1000).grid(row=1, column=0, sticky='w', pady=6)
        controls = ttk.Frame(outer)
        controls.grid(row=2, column=0, sticky='ew', pady=6)
        self.scan_button = ttk.Button(controls, text='分析 C 盘', command=self.start_scan)
        self.scan_button.pack(side='left')
        self.stop_button = ttk.Button(controls, text='停止', command=self.cancel.set, state='disabled')
        self.stop_button.pack(side='left', padx=6)
        self.cache_button = ttk.Button(controls, text='查看 C 盘可清理文件…', command=self.open_cache)
        self.cache_button.pack(side='left')
        ttk.Button(controls, text='系统临时文件', command=lambda: os.startfile('ms-settings:storagesense')).pack(side='right')
        ttk.Button(controls, text='已安装应用', command=lambda: os.startfile('ms-settings:appsfeatures')).pack(side='right', padx=6)
        ttk.Label(outer, text='缓存：确认后可再生成。个人资料：先备份或迁移。系统 / 软件：使用设置清理或卸载。',
                  style='Muted.TLabel', wraplength=1000).grid(row=3, column=0, sticky='w', pady=6)
        book = ttk.Notebook(outer)
        book.grid(row=4, column=0, sticky='nsew')
        self.trees = []
        for title in ('清理建议', '目录占用排行（展开查看）'):
            frame = ttk.Frame(book)
            book.add(frame, text=title)
            frame.rowconfigure(0, weight=1)
            frame.columnconfigure(0, weight=1)
            tree = ttk.Treeview(frame, columns=('size', 'decision', 'advice'), show='tree headings', selectmode='browse')
            for col, text, width in (('#0', '目录 / 文件', 350), ('size', '逻辑大小', 100),
                                     ('decision', '能不能删', 155), ('advice', '建议做法', 430)):
                tree.heading(col, text=text)
                tree.column(col, width=width, minwidth=90)
            sy = ttk.Scrollbar(frame, orient='vertical', command=tree.yview)
            sx = ttk.Scrollbar(frame, orient='horizontal', command=tree.xview)
            tree.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
            tree.grid(row=0, column=0, sticky='nsew')
            sy.grid(row=0, column=1, sticky='ns')
            sx.grid(row=1, column=0, sticky='ew')
            tree.bind('<<TreeviewSelect>>', lambda e: self.show_detail(e.widget))
            tree.bind('<<TreeviewOpen>>', lambda e: self.expand(e.widget))
            tree.tag_configure('cache', foreground='#16723c')
            tree.tag_configure('protected', foreground='#65748b')
            self.trees.append(tree)
        actions = ttk.Frame(outer)
        actions.grid(row=5, column=0, sticky='ew', pady=(8, 4))
        ttk.Label(actions, text='选中项目后在下方查看用途、影响和限制。').pack(side='left')
        ttk.Button(actions, text='打开选中位置', command=self.reveal).pack(side='right')
        self.detail = tk.Text(outer, height=5, wrap='word', font=('Microsoft YaHei UI', 10), relief='flat', padx=8, pady=6)
        self.detail.grid(row=6, column=0, sticky='ew')
        self.set_detail('目录大小不是可清理空间。父目录包含子目录，不可重复相加。\n'
                        '只读扫描跳过链接和云占位符；权限限制会注明。硬链接、压缩及系统保留空间可能导致逻辑大小与磁盘占用不同。\n'
                        '回收站中的文件仍占空间；清空后才释放。所有清理仍需逐项勾选和确认。')
        self.progress = ttk.Progressbar(outer, mode='indeterminate')
        self.progress.grid(row=7, column=0, sticky='ew', pady=6)
        ttk.Label(outer, textvariable=self.status, style='Muted.TLabel', wraplength=1000).grid(row=8, column=0, sticky='w')

    def set_detail(self, text):
        self.detail.configure(state='normal')
        self.detail.delete('1.0', 'end')
        self.detail.insert('1.0', text)
        self.detail.configure(state='disabled')

    def start_scan(self):
        if self.busy:
            return
        self.busy = True
        self.cancel.clear()
        self.scan_button.configure(state='disabled')
        self.stop_button.configure(state='normal')
        self.progress.start(12)
        self.status.set('正在分析；所有文件均计入目录总量，不受旧版 500 MB 阈值限制…')
        def worker():
            try:
                result = audit_drive(self.scan_root, lambda t: self.events.put(('progress', t)), self.cancel)
                self.events.put(('result', result))
            except Exception as exc:
                self.events.put(('error', str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def insert(self, tree, parent, node, lazy=False):
        decision, _, advice = explain(node.path, self.user, self.rules)
        name = os.path.basename(node.path.rstrip('\\/')) or node.path
        note = '（统计受限）' if node.errors or node.links or self.result.cancelled else ''
        item = tree.insert(parent, 'end', text=name + note,
                           values=(format_size(node.size), decision, advice),
                           tags=('cache',) if decision == '可清理缓存' else ('protected',))
        self.paths[(str(tree), item)] = node.path
        if lazy and node.directory and key(node.path) in self.parent_keys:
            tree.insert(item, 'end', text='展开加载…', tags=('placeholder',))
        return item

    def render(self):
        self.paths.clear()
        self.parent_keys = {n.parent for n in self.result.nodes.values()}
        for tree in self.trees:
            tree.delete(*tree.get_children())
        rows = recommendations(self.result, self.user, self.rules)
        for node in rows:
            self.insert(self.trees[0], '', node)
        if not rows:
            self.trees[0].insert('', 'end', text='本次未找到可直接建议的缓存；请查看目录占用排行。')
        tree = self.trees[1]
        top = self.insert(tree, '', self.result.nodes[key(self.result.root)], lazy=True)
        self.load_children(tree, top)
        tree.item(top, open=True)
        root = self.result.nodes[key(self.result.root)]
        used = self.result.total - self.result.free
        self.capacity.set(f'可用 {format_size(self.result.free)} / 总容量 {format_size(self.result.total)}；'
                          f'系统报告已用 {format_size(used)}。文件逻辑大小 {format_size(root.size)}（口径不同）。')
        self.status.set(f'{"已停止，以下为部分结果" if self.result.cancelled else "分析完成"} · {root.files:,} 个文件 · '
                        f'{self.result.seconds:.0f} 秒 · 无法读取 {root.errors:,} 项 · 跳过链接/云文件 {root.links:,} 项。')
        self.set_detail('清理建议仅表示已识别的位置，不代表其中所有文件都适合现在删除。\n'
                        '点“查看 C 盘可清理文件…”重新扫描满足保留天数的具体文件；默认不勾选。\n'
                        '系统更新、旧系统和组件使用“系统临时文件”；软件本体使用“已安装应用”。\n'
                        '目录排行可逐层展开，每层显示最大的 500 项；小文件也已计入目录大小。')

    def load_children(self, tree, item):
        path = self.paths.get((str(tree), item))
        if not path:
            return
        children = tree.get_children(item)
        if not children or 'placeholder' not in tree.item(children[0], 'tags'):
            return
        tree.delete(*children)
        rows = self.result.children(path)
        for node in rows[:500]:
            self.insert(tree, item, node, lazy=True)
        if len(rows) > 500:
            tree.insert(item, 'end', text=f'仅展示最大的 500 项，共 {len(rows):,} 项；总大小包含全部项目。')

    def expand(self, tree):
        self.load_children(tree, tree.focus())

    def show_detail(self, tree):
        selected = tree.selection()
        path = self.paths.get((str(tree), selected[0])) if selected else None
        if not path:
            return
        self.current_path = path
        node = self.result.nodes[key(path)]
        decision, purpose, advice = explain(path, self.user, self.rules)
        self.set_detail(f'{path}\n判断：{decision}。用途：{purpose}\n建议：{advice}\n'
                        f'逻辑大小 {format_size(node.size)}，{node.files:,} 个文件。'
                        f'无法读取 {node.errors} 项，跳过链接/云文件 {node.links} 项。'
                        '父目录包含子目录；此窗口不提供整目录删除。')

    def reveal(self):
        path = getattr(self, 'current_path', None)
        if path:
            subprocess.Popen(['explorer.exe', '/select,', path])

    def open_cache(self):
        if self.review_cache():
            self.window.lower()
            self.window.master.lift()

    def poll(self):
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == 'progress':
                    self.status.set(value)
                    continue
                self.busy = False
                self.progress.stop()
                self.scan_button.configure(state='normal')
                self.stop_button.configure(state='disabled')
                if kind == 'result':
                    self.result = value
                    self.render()
                else:
                    self.status.set('分析未完成。')
                    messagebox.showerror('分析未完成', value, parent=self.window)
        except queue.Empty:
            pass
        self.timer = self.window.after(100, self.poll)

    def close(self):
        if self.busy:
            self.cancel.set()
            self.status.set('正在停止扫描，结束后可关闭。')
            return
        self.window.after_cancel(self.timer)
        self.window.destroy()

"""Application storage review window: scan, explain, confirm, recycle."""
from datetime import datetime
import os
from pathlib import Path
import queue
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from core import MIB, format_size
from app_inventory import (PROGRAM_KINDS, export_inventory, recycle_locations,
                           related_processes, scan_apps, selected_roots)


class AppStorageWindow:
    def __init__(self, parent, user, roots, report_dir):
        self.window = tk.Toplevel(parent)
        self.window.title('应用占用 · 数据 / 缓存 / 程序')
        width = min(1360, self.window.winfo_screenwidth() - 60)
        height = min(860, self.window.winfo_screenheight() - 100)
        self.window.geometry(f'{width}x{height}+30+30')
        self.window.minsize(min(1000, width), min(650, height))
        self.user, self.roots, self.report_dir = user, roots, Path(report_dir)
        self.inventory = None
        self.selected = set()
        self.busy = False
        self.stale = False
        self.cancel = threading.Event()
        self.events = queue.Queue()
        self.search = tk.StringVar()
        self.min_mb = tk.StringVar(value='100')
        self.status = tk.StringVar(value='扫描应用目录、安装记录及常见数据位置。所有项目默认不勾选。')
        self.chosen = tk.StringVar(value='已勾选 0 个目录')
        self._build()
        self.window.protocol('WM_DELETE_WINDOW', self.close)
        self.poll_id = self.window.after(100, self.poll)

    def _build(self):
        outer = ttk.Frame(self.window, padding=16)
        outer.pack(fill='both', expand=True)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(5, weight=1)
        ttk.Label(outer, text='应用占用', font=('Microsoft YaHei UI', 21, 'bold')).grid(row=0, column=0, sticky='w')
        ttk.Label(outer, text='展开应用查看目录。数据包含配置、聊天附件和离线资源；缓存已计入总量。程序本体请通过卸载处理。',
                  wraplength=1050).grid(row=1, column=0, sticky='w', pady=(6, 12))
        bar = ttk.Frame(outer)
        bar.grid(row=2, column=0, sticky='ew')
        bar.columnconfigure(1, weight=1)
        self.scan_button = ttk.Button(bar, text='扫描应用占用', command=self.start_scan)
        self.scan_button.grid(row=0, column=0, sticky='w')
        self.stop_button = ttk.Button(bar, text='停止', state='disabled', command=self.cancel.set)
        self.stop_button.grid(row=0, column=1, sticky='w', padx=8)
        ttk.Button(bar, text='应用卸载', command=lambda: os.startfile('ms-settings:appsfeatures')).grid(row=0, column=2)
        ttk.Button(bar, text='导出清单', command=self.export).grid(row=0, column=3, padx=(8, 0))
        actions = ttk.Frame(outer)
        actions.grid(row=3, column=0, sticky='ew', pady=(10, 8))
        actions.columnconfigure(0, weight=1)
        ttk.Label(actions, textvariable=self.chosen, wraplength=250).grid(row=0, column=0, sticky='w')
        self.recycle_button = ttk.Button(actions, text='移到回收站…', command=lambda: self.prepare(False), state='disabled')
        self.recycle_button.grid(row=0, column=1, padx=8)
        self.force_button = ttk.Button(actions, text='关闭后台进程后回收…', style='Accent.TButton',
                                       command=lambda: self.prepare(True), state='disabled')
        self.force_button.grid(row=0, column=2, sticky='e')
        filters = ttk.Frame(outer)
        filters.grid(row=4, column=0, sticky='ew', pady=(0, 8))
        ttk.Label(filters, text='搜索应用 / 路径').pack(side='left')
        entry = ttk.Entry(filters, textvariable=self.search, width=26)
        entry.pack(side='left', padx=8)
        entry.bind('<Return>', lambda _: self.render())
        ttk.Label(filters, text='应用总量 ≥').pack(side='left')
        ttk.Spinbox(filters, textvariable=self.min_mb, values=(0, 10, 100, 500, 1000), width=6).pack(side='left', padx=6)
        ttk.Label(filters, text='MB').pack(side='left')
        ttk.Button(filters, text='筛选', command=self.render).pack(side='left', padx=8)
        ttk.Button(filters, text='取消全部勾选', command=self.clear_selection).pack(side='right')
        table = ttk.Frame(outer)
        table.grid(row=5, column=0, sticky='nsew')
        table.columnconfigure(0, weight=1)
        table.rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(table, columns=('check', 'kind', 'size', 'path'), show='tree headings', height=5)
        for col, title, width in (('#0', '应用 / 目录（缓存已计入总量）', 320), ('check', '勾选', 55),
                                  ('kind', '类型', 145), ('size', '大小', 115), ('path', '实际路径 / 总量说明', 660)):
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, minwidth=45, stretch=col in ('#0', 'path'))
        self.tree.grid(row=0, column=0, sticky='nsew')
        vertical = ttk.Scrollbar(table, orient='vertical', command=self.tree.yview)
        horizontal = ttk.Scrollbar(table, orient='horizontal', command=self.tree.xview)
        vertical.grid(row=0, column=1, sticky='ns')
        horizontal.grid(row=1, column=0, sticky='ew')
        self.tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.tree.tag_configure('protected', foreground='#768096')
        self.tree.tag_configure('checked', background='#e8f0ff')
        self.tree.bind('<Button-1>', self.click)
        self.tree.bind('<space>', self.toggle_keyboard)
        self.tree.bind('<<TreeviewSelect>>', self.show_detail)
        heading = ttk.Frame(outer)
        heading.grid(row=6, column=0, sticky='ew', pady=(8, 3))
        ttk.Label(heading, text='用途与回收影响（只回收手动勾选的目录）').pack(side='left')
        ttk.Button(heading, text='打开所在位置', command=self.reveal).pack(side='right')
        detail_frame = ttk.Frame(outer)
        detail_frame.grid(row=7, column=0, sticky='ew')
        detail_frame.columnconfigure(0, weight=1)
        self.detail = tk.Text(detail_frame, height=4, wrap='word', font=('Microsoft YaHei UI', 10),
                              relief='flat', padx=8, pady=6)
        self.detail.grid(row=0, column=0, sticky='ew')
        detail_scroll = ttk.Scrollbar(detail_frame, orient='vertical', command=self.detail.yview)
        detail_scroll.grid(row=0, column=1, sticky='ns')
        self.detail.configure(yscrollcommand=detail_scroll.set, state='disabled')
        self.progress = ttk.Progressbar(outer, mode='indeterminate')
        self.progress.grid(row=8, column=0, sticky='ew', pady=(8, 4))
        ttk.Label(outer, textvariable=self.status, wraplength=1050).grid(row=9, column=0, sticky='w')

    def set_busy(self, busy):
        self.busy = busy
        self.scan_button.configure(state='disabled' if busy else 'normal')
        self.stop_button.configure(state='normal' if busy else 'disabled')
        self.progress.start(12) if busy else self.progress.stop()
        self.update_selection()

    def start_scan(self):
        if self.busy:
            return
        self.inventory = None
        self.selected.clear()
        self.stale = False
        self.cancel.clear()
        self.render()
        self.set_busy(True)
        self.status.set('统计应用数据、缓存及程序目录…')
        def worker():
            try:
                result = scan_apps(self.user, self.roots, lambda t: self.events.put(('progress', t)), self.cancel)
                self.events.put(('scan', result))
            except Exception as exc:
                self.events.put(('error', str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def render(self):
        expanded = {row for row in self.tree.get_children() if self.tree.item(row, 'open')}
        current = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        if not self.inventory:
            self.update_selection()
            return
        try:
            minimum = max(0, int(self.min_mb.get())) * MIB
        except ValueError:
            self.status.set('筛选大小请输入非负整数。')
            return
        needle = self.search.get().casefold().strip()
        totals = self.inventory.totals()
        for group_index, (owner, total) in enumerate(sorted(totals.items(), key=lambda pair: pair[1]['total'], reverse=True)):
            group_items = [(i, item) for i, item in enumerate(self.inventory.locations) if item.app == owner]
            if total['total'] < minimum or (needle and not any(needle in (owner + ' ' + item.path).casefold() for _, item in group_items)):
                continue
            parent = f'app:{group_index}'
            text = f'程序/混合 {format_size(total["program"])} · 数据/资源 {format_size(total["data"])} · 其中缓存 {format_size(total["cache"])}'
            self.tree.insert('', 'end', iid=parent, text=owner, open=parent in expanded,
                             values=('', '应用合计', format_size(total['total']), text))
            for index, item in sorted(group_items, key=lambda pair: (bool(pair[1].parent_path), -pair[1].total_bytes)):
                check = '☑' if index in self.selected else '☐' if item.selectable and not self.stale else '—'
                label = ('↳ 缓存 · ' if item.parent_path else '') + os.path.basename(item.path)
                size = format_size(item.total_bytes) + ('（不完整）' if item.issues else '')
                self.tree.insert(parent, 'end', iid=str(index), text=label,
                                 values=(check, item.kind, size, item.path),
                                 tags=('checked',) if index in self.selected else ('protected',) if not item.selectable else ())
        if current and self.tree.exists(current[0]):
            self.tree.selection_set(current[0])
        self.update_selection()

    def update_selection(self):
        items = selected_roots([self.inventory.locations[i] for i in self.selected]) if self.inventory else []
        total = sum(item.total_bytes for item in items)
        self.chosen.set(f'已勾选 {len(items)} 个目录 · {format_size(total)}')
        state = 'normal' if items and not self.busy and not self.stale else 'disabled'
        self.recycle_button.configure(state=state)
        self.force_button.configure(state=state)

    def toggle(self, row):
        if self.busy or self.stale or not row or row.startswith('app:'):
            return
        index = int(row)
        item = self.inventory.locations[index]
        if item.selectable:
            self.selected.symmetric_difference_update({index})
            self.render()
        else:
            self.tree.selection_set(row)
            self.show_detail()

    def click(self, event):
        if self.tree.identify_column(event.x) == '#1':
            self.toggle(self.tree.identify_row(event.y))

    def toggle_keyboard(self, _):
        current = self.tree.selection()
        if current:
            self.toggle(current[0])
        return 'break'

    def clear_selection(self):
        if not self.busy:
            self.selected.clear()
            self.render()

    def current(self):
        selected = self.tree.selection()
        if selected and not selected[0].startswith('app:') and self.inventory:
            return self.inventory.locations[int(selected[0])]

    def show_detail(self, _=None):
        item = self.current()
        if not item:
            return
        aliases = '\n'.join(p for p in item.aliases if os.path.normcase(p) != os.path.normcase(item.path))
        text = (f'{item.app} · {item.kind}\n实际路径：{item.path}\n'
                f'{"原入口（已迁移）：" + aliases + chr(10) if aliases else ""}'
                f'大小：{format_size(item.total_bytes)}，{item.total_files:,} 个文件。用途：{item.purpose}\n')
        if item.parent_path:
            text += f'已包含在上级目录总量内：{item.parent_path}\n'
        if item.kind in PROGRAM_KINDS:
            text += '程序或混合目录：使用上方“应用卸载”；不提供整目录强制回收。\n'
        elif item.selectable:
            text += '回收的是整个所选目录，包含近期文件；不使用主窗口的保留天数。清空回收站后才释放空间。\n'
        else:
            text += '仅统计；归属未可靠识别、正在使用的工具自身数据，或目录包含未扫描项目。\n'
        if item.issues:
            text += '扫描限制：' + '\n'.join(item.issues[:5])
        self.detail.configure(state='normal')
        self.detail.delete('1.0', 'end')
        self.detail.insert('1.0', text)
        self.detail.configure(state='disabled')

    def reveal(self):
        item = self.current()
        if item and os.path.exists(item.path):
            subprocess.Popen(['explorer.exe', '/select,', item.path])

    def prepare(self, force):
        if self.busy or self.stale or not self.selected or not self.inventory:
            return
        items = selected_roots([self.inventory.locations[i] for i in sorted(self.selected)])
        self.cancel.clear()
        self.set_busy(True)
        self.status.set('检查与所选应用关联的后台进程，仅准备操作清单…')
        def worker():
            try:
                processes = related_processes(items, self.inventory) if force else []
                self.events.put(('prepared', (items, processes, force)))
            except Exception as exc:
                self.events.put(('error', str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def confirm(self, items, processes, force):
        dialog = tk.Toplevel(self.window)
        dialog.title('确认所选应用目录与后台进程')
        dialog.geometry('850x570')
        dialog.transient(self.window)
        dialog.grab_set()
        dialog.columnconfigure(0, weight=1)
        dialog.rowconfigure(1, weight=1)
        ttk.Label(dialog, text='仅移到回收站；不会改为永久删除。整目录操作包括近期文件。',
                  wraplength=800).grid(row=0, column=0, sticky='w', padx=16, pady=12)
        box = ttk.Frame(dialog)
        box.grid(row=1, column=0, sticky='nsew', padx=16)
        box.columnconfigure(0, weight=1)
        box.rowconfigure(0, weight=1)
        text = tk.Text(box, wrap='word', font=('Microsoft YaHei UI', 10))
        text.grid(row=0, column=0, sticky='nsew')
        scrollbar = ttk.Scrollbar(box, orient='vertical', command=text.yview)
        scrollbar.grid(row=0, column=1, sticky='ns')
        text.configure(yscrollcommand=scrollbar.set)
        description = '\n\n'.join(f'{item.app} · {item.kind} · {format_size(item.total_bytes)}\n{item.path}\n{item.purpose}' for item in items)
        if force:
            description += '\n\n将先请求退出以下进程；2 秒后仍未退出的会强制结束，未保存的内容可能丢失：\n'
            description += '\n'.join(f'{p.name} · PID {p.pid}\n{p.path}' for p in processes) or '未发现可可靠关联的后台进程；只尝试回收，锁定项会报告失败。'
        description += '\n\n关闭程序可能写入最后状态；确认范围是这些完整目录，回收前会重新检查。目录链接、权限不足或仍被其他程序锁定的目标会跳过。'
        text.insert('1.0', description)
        text.configure(state='disabled')
        accepted = tk.BooleanVar(value=False)
        ttk.Checkbutton(dialog, text='我已查看目录与进程，确认移走这些本地数据，并接受所列进程退出的影响。',
                        variable=accepted).grid(row=2, column=0, sticky='w', padx=16, pady=12)
        answer = []
        buttons = ttk.Frame(dialog)
        buttons.grid(row=3, column=0, sticky='e', padx=16, pady=(0, 16))
        ttk.Button(buttons, text='取消', command=dialog.destroy).pack(side='left', padx=8)
        def approve():
            if accepted.get():
                answer.append(True)
                dialog.destroy()
        execute = ttk.Button(buttons, text='确认回收', state='disabled', command=approve)
        execute.pack(side='left')
        accepted.trace_add('write', lambda *_: execute.configure(state='normal' if accepted.get() else 'disabled'))
        self.window.wait_window(dialog)
        return bool(answer)

    def execute(self, items, processes, force):
        self.cancel.clear()
        self.set_busy(True)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        path = self.report_dir / ('app-recycle-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '.jsonl')
        def worker():
            try:
                result = recycle_locations(items, self.roots, processes, path, force,
                                           lambda t: self.events.put(('progress', t)), self.cancel)
                self.events.put(('recycled', (result, path)))
            except Exception as exc:
                self.events.put(('error', str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def export(self):
        if not self.inventory:
            return
        path = filedialog.asksaveasfilename(parent=self.window, title='导出应用占用', defaultextension='.json',
                                          initialfile='应用占用-' + datetime.now().strftime('%Y%m%d') + '.json')
        if path:
            include_private = messagebox.askyesno('导出隐私选项',
                '是否包含应用名称、完整路径和错误详情？这些信息可能暴露账号和个人资料。\n选择“否”导出不含名称和路径的汇总。',
                parent=self.window, default='no')
            export_inventory(self.inventory, path, include_private=include_private)
            self.status.set(f'已导出：{path}')

    def poll(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == 'progress':
                    self.status.set(payload)
                elif kind == 'scan':
                    self.inventory = payload
                    self.set_busy(False)
                    self.render()
                    self.report_dir.mkdir(parents=True, exist_ok=True)
                    export_inventory(payload, self.report_dir / 'latest-app-storage.json', include_private=True)
                    self.status.set(f'{"部分扫描" if payload.cancelled else "扫描完成"}：{len(payload.totals())} 个应用分组，'
                                    f'{len(payload.locations)} 个目录；耗时 {payload.seconds:.0f} 秒，扫描限制 {len(payload.errors)} 项。')
                elif kind == 'prepared':
                    self.set_busy(False)
                    if not self.cancel.is_set() and self.confirm(*payload):
                        self.execute(*payload)
                    else:
                        self.status.set('已取消，没有关闭进程或回收文件。')
                elif kind == 'recycled':
                    result, path = payload
                    self.stale = True
                    self.selected.clear()
                    self.set_busy(False)
                    self.render()
                    self.status.set('操作已结束，请重新扫描查看剩余目录。')
                    messagebox.showinfo('回收结果', f'成功 {result["success"]} 个目录，跳过 {result["skipped"]} 个。\n'
                        f'移到回收站：{format_size(result["recycled_bytes"])}；清空回收站后才释放空间。\n'
                        f'日志：{path}\n' + '\n'.join(result['errors'][:3]), parent=self.window)
                elif kind == 'error':
                    self.stale = True
                    self.set_busy(False)
                    self.status.set('操作未完成。已处理的项目见日志；重新扫描后再决定。')
                    messagebox.showerror('操作未完成', payload, parent=self.window)
        except queue.Empty:
            pass
        self.poll_id = self.window.after(100, self.poll)

    def close(self):
        if self.busy:
            self.cancel.set()
            self.status.set('正在停止，当前 Windows 操作结束后可关闭。')
            return
        self.window.after_cancel(self.poll_id)
        self.window.destroy()

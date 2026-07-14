# -*- coding: utf-8 -*-
"""GUI анализатора дампов BSOD на Tkinter (стандартная библиотека)."""

from __future__ import annotations

import queue
import threading
from pathlib import Path
from typing import Dict, List, Optional

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import autofix as autofix_mod
from . import config as config_mod
from . import dump_finder, dump_parser, remediation, report
from .ai_backends import AIRunner
from .dump_finder import DumpFile
from .dump_parser import DumpAnalysis

APP_TITLE = "BSOD Dump Analyzer — анализатор синих экранов"


class BSODAnalyzerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1180x760")
        self.root.minsize(940, 600)

        self.config = config_mod.load_config()
        self.ai = AIRunner(config_mod.backends_from_config(self.config))

        self.dumps: List[DumpFile] = []
        self.current_analysis: Optional[DumpAnalysis] = None
        self.current_plan: List[remediation.FixStep] = []
        self._task_queue: "queue.Queue" = queue.Queue()

        self._build_ui()
        self._poll_queue()
        self.refresh_dumps()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        toolbar = ttk.Frame(self.root, padding=(8, 6))
        toolbar.pack(side=tk.TOP, fill=tk.X)

        ttk.Button(toolbar, text="🔄 Обновить список",
                   command=self.refresh_dumps).pack(side=tk.LEFT)
        ttk.Button(toolbar, text="📁 Добавить папку…",
                   command=self.add_folder).pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(toolbar, text="🗑 Удалить выбранные",
                   command=self.delete_selected).pack(side=tk.LEFT, padx=(6, 0))
        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(
            side=tk.LEFT, fill=tk.Y, padx=10)
        ttk.Button(toolbar, text="⚙ Настройки ИИ…",
                   command=self.open_settings).pack(side=tk.LEFT)

        # Основная область: слева список, справа вкладки.
        main = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 6))

        self._build_dump_list(main)
        self._build_detail_panel(main)

        # Строка состояния.
        self.status_var = tk.StringVar(value="Готово.")
        status = ttk.Frame(self.root)
        status.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Separator(status).pack(fill=tk.X)
        self.progress = ttk.Progressbar(status, mode="indeterminate", length=140)
        self.progress.pack(side=tk.RIGHT, padx=8, pady=3)
        ttk.Label(status, textvariable=self.status_var,
                  anchor=tk.W).pack(side=tk.LEFT, fill=tk.X, padx=8, pady=3)

    def _build_dump_list(self, parent: ttk.PanedWindow) -> None:
        left = ttk.Frame(parent)
        parent.add(left, weight=1)

        ttk.Label(left, text="Найденные дампы:",
                  font=("", 10, "bold")).pack(anchor=tk.W, pady=(0, 4))

        cols = ("name", "date", "size", "kind")
        self.tree = ttk.Treeview(left, columns=cols, show="headings",
                                 selectmode="extended", height=18)
        self.tree.heading("name", text="Файл")
        self.tree.heading("date", text="Дата")
        self.tree.heading("size", text="Размер")
        self.tree.heading("kind", text="Тип")
        self.tree.column("name", width=190)
        self.tree.column("date", width=130, anchor=tk.CENTER)
        self.tree.column("size", width=70, anchor=tk.E)
        self.tree.column("kind", width=150)

        vsb = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.LEFT, fill=tk.Y)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", lambda e: self.analyze_selected())

    def _build_detail_panel(self, parent: ttk.PanedWindow) -> None:
        right = ttk.Frame(parent)
        parent.add(right, weight=2)

        # Панель кнопок анализа.
        actions = ttk.Frame(right)
        actions.pack(fill=tk.X, pady=(0, 6))

        self.analyze_btn = ttk.Button(actions, text="🔬 Анализировать",
                                      command=self.analyze_selected)
        self.analyze_btn.pack(side=tk.LEFT)

        ttk.Label(actions, text="  ИИ:").pack(side=tk.LEFT, padx=(10, 2))
        self.backend_var = tk.StringVar()
        self.backend_combo = ttk.Combobox(actions, textvariable=self.backend_var,
                                          state="readonly", width=30)
        self.backend_combo.pack(side=tk.LEFT)
        self._refresh_backend_combo()

        self.ai_btn = ttk.Button(actions, text="🤖 Анализ через ИИ",
                                 command=self.analyze_with_ai)
        self.ai_btn.pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(actions, text="📋 Копировать промпт",
                   command=self.copy_prompt).pack(side=tk.LEFT, padx=(6, 0))

        self.autofix_btn = ttk.Button(actions, text="🛠 Autofix",
                                      command=self.run_autofix)
        self.autofix_btn.pack(side=tk.RIGHT)

        # Вкладки с результатами.
        self.nb = ttk.Notebook(right)
        self.nb.pack(fill=tk.BOTH, expand=True)

        self.report_text = self._make_text_tab("📄 Отчёт")
        self.tech_text = self._make_text_tab("🔧 Технические детали")
        self.plan_text = self._make_text_tab("🩺 Что делать")
        self.ai_text = self._make_text_tab("🤖 Ответ ИИ")

        self._set_text(self.report_text,
                       "Выберите дамп слева и нажмите «Анализировать».\n\n"
                       "Если запущено не в Windows — списка дампов не будет; "
                       "можно добавить папку с .dmp вручную для теста.")

    def _make_text_tab(self, title: str) -> tk.Text:
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text=title)
        text = tk.Text(frame, wrap=tk.WORD, font=("Consolas", 10),
                       padx=10, pady=8, undo=False)
        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text.yview)
        text.configure(yscrollcommand=vsb.set, state=tk.DISABLED)
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.LEFT, fill=tk.Y)
        return text

    # ------------------------------------------------------------- helpers
    def _set_text(self, widget: tk.Text, content: str) -> None:
        widget.configure(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert("1.0", content)
        widget.configure(state=tk.DISABLED)

    def _status(self, msg: str) -> None:
        self.status_var.set(msg)

    def _busy(self, on: bool) -> None:
        if on:
            self.progress.start(12)
        else:
            self.progress.stop()

    def _refresh_backend_combo(self) -> None:
        avail = self.ai.available()
        labels = [b.label for b in avail]
        self._backend_labels: Dict[str, str] = {b.label: b.key for b in avail}
        self.backend_combo["values"] = labels
        if labels and not self.backend_var.get():
            self.backend_var.set(labels[0])

    def _selected_dumps(self) -> List[DumpFile]:
        result = []
        for item in self.tree.selection():
            idx = int(item)
            if 0 <= idx < len(self.dumps):
                result.append(self.dumps[idx])
        return result

    # -------------------------------------------------------------- actions
    def refresh_dumps(self) -> None:
        self._status("Поиск дампов…")
        extra = [Path(p) for p in self.config.get("extra_locations", [])]
        try:
            self.dumps = dump_finder.find_dumps(extra_locations=extra)
        except Exception as exc:  # noqa: BLE001 — не роняем GUI
            messagebox.showerror("Ошибка", f"Не удалось найти дампы:\n{exc}")
            self.dumps = []

        self.tree.delete(*self.tree.get_children())
        for i, d in enumerate(self.dumps):
            self.tree.insert("", tk.END, iid=str(i),
                             values=(d.name, d.mtime_str, d.size_human, d.kind_ru))
        if self.dumps:
            self._status(f"Найдено дампов: {len(self.dumps)}. "
                         f"Свежий: {self.dumps[0].name}")
        else:
            self._status("Дампы не найдены. Это хорошо (значит, синих экранов "
                         "давно не было) или запущено не в Windows.")

    def add_folder(self) -> None:
        folder = filedialog.askdirectory(title="Выберите папку с дампами")
        if not folder:
            return
        extra = self.config.setdefault("extra_locations", [])
        if folder not in extra:
            extra.append(folder)
            config_mod.save_config(self.config)
        self.refresh_dumps()

    def delete_selected(self) -> None:
        selected = self._selected_dumps()
        if not selected:
            messagebox.showinfo("Удаление", "Сначала выберите дампы в списке.")
            return
        names = "\n".join("  • " + d.name for d in selected)
        if not messagebox.askyesno(
                "Подтверждение удаления",
                f"Удалить безвозвратно {len(selected)} файл(ов)?\n\n{names}"):
            return
        outcome = dump_finder.delete_dumps(selected)
        errors = [(d, e) for d, e in outcome if e]
        if errors:
            msg = "\n".join(f"{d.name}: {e}" for d, e in errors)
            messagebox.showwarning(
                "Удалено с ошибками",
                "Часть файлов не удалилась (возможно, нужны права "
                f"администратора):\n\n{msg}")
        self.refresh_dumps()

    def _on_select(self, _event=None) -> None:
        sel = self._selected_dumps()
        if len(sel) == 1:
            self._status(f"Выбран: {sel[0].name}  ({sel[0].path})")

    def analyze_selected(self) -> None:
        sel = self._selected_dumps()
        if len(sel) != 1:
            messagebox.showinfo("Анализ",
                                "Выберите ровно один дамп для анализа.")
            return
        dump = sel[0]
        self._status(f"Анализ {dump.name}…")
        self._busy(True)
        self.analyze_btn.configure(state=tk.DISABLED)
        use_cdb = bool(self.config.get("use_cdb", True))
        cdb_path = self.config.get("cdb_path") or None

        def work():
            try:
                analysis = dump_parser.analyze(
                    dump.path, use_cdb=use_cdb, cdb_exe=cdb_path)
                self._task_queue.put(("analysis_done", analysis))
            except Exception as exc:  # noqa: BLE001
                self._task_queue.put(("analysis_error", str(exc)))

        threading.Thread(target=work, daemon=True).start()

    def _on_analysis_done(self, analysis: DumpAnalysis) -> None:
        self._busy(False)
        self.analyze_btn.configure(state=tk.NORMAL)
        self.current_analysis = analysis

        self._set_text(self.report_text, report.build_human_report(analysis))

        tech = self._build_tech_text(analysis)
        self._set_text(self.tech_text, tech)

        self.current_plan = remediation.build_plan(analysis)
        self._set_text(self.plan_text, remediation.format_plan(self.current_plan))

        self.nb.select(0)
        cdb_note = " (с cdb)" if analysis.cdb_used else " (без cdb)"
        self._status(f"Анализ завершён{cdb_note}: {analysis.path.name}")

    def _build_tech_text(self, a: DumpAnalysis) -> str:
        lines = [
            f"Файл: {a.path}",
            f"Формат дампа: {a.dump_format}",
            f"Архитектура: {a.arch or 'н/д'}",
        ]
        if a.bugcheck_code is not None:
            lines.append(f"Bugcheck: {a.bugcheck_hex}")
            for i, p in enumerate(a.bugcheck_params, start=1):
                lines.append(f"  Arg{i}: 0x{p:016X}")
        if a.exception_code is not None:
            lines.append(f"Exception code: 0x{a.exception_code:08X}")
        if a.probable_module:
            lines.append(f"Probable module: {a.probable_module}")
        if a.failure_bucket:
            lines.append(f"Failure bucket: {a.failure_bucket}")
        if a.parse_error:
            lines.append(f"Parse note: {a.parse_error}")
        lines.append("")
        if a.cdb_output:
            lines.append("=" * 60)
            lines.append("ПОЛНЫЙ ВЫВОД cdb !analyze -v:")
            lines.append("=" * 60)
            lines.append(a.cdb_output)
        else:
            lines.append("cdb не запускался (не найден или отключён в "
                         "настройках). Установите Debugging Tools for Windows "
                         "для детального разбора.")
        return "\n".join(lines)

    def _on_analysis_error(self, err: str) -> None:
        self._busy(False)
        self.analyze_btn.configure(state=tk.NORMAL)
        self._status("Ошибка анализа.")
        messagebox.showerror("Ошибка анализа", err)

    # ------------------------------------------------------------------ AI
    def _ensure_analysis(self) -> bool:
        if self.current_analysis is None:
            messagebox.showinfo("Сначала анализ",
                                "Сначала проанализируйте дамп (кнопка "
                                "«Анализировать»).")
            return False
        return True

    def copy_prompt(self) -> None:
        if not self._ensure_analysis():
            return
        prompt = report.build_ai_prompt(self.current_analysis)
        self.root.clipboard_clear()
        self.root.clipboard_append(prompt)
        self._status("Промпт скопирован в буфер обмена — вставьте его в любой "
                     "ИИ-чат (Claude Desktop, Grok Build, ChatGPT).")
        messagebox.showinfo("Скопировано",
                            "Готовый промпт с деталями дампа скопирован в буфер "
                            "обмена.\n\nВставьте его в Claude Desktop, Grok Build "
                            "или любой другой чат.")

    def analyze_with_ai(self) -> None:
        if not self._ensure_analysis():
            return
        label = self.backend_var.get()
        key = getattr(self, "_backend_labels", {}).get(label)
        if not key:
            messagebox.showinfo(
                "Нет доступных ИИ",
                "Не найдено ни одного установленного ИИ-CLI.\n\n"
                "Варианты:\n"
                "• Установите Claude Code / Codex CLI / Grok CLI и войдите в "
                "аккаунт;\n"
                "• Либо нажмите «Копировать промпт» и вставьте его в "
                "Claude Desktop / Grok Build вручную.")
            return

        backend = self.ai.by_key(key)
        prompt = report.build_ai_prompt(self.current_analysis)

        if backend and backend.clipboard_only:
            self.copy_prompt()
            return

        self._status(f"Отправка в {label}… (может занять до нескольких минут)")
        self._busy(True)
        self.ai_btn.configure(state=tk.DISABLED)
        self.nb.select(3)
        self._set_text(self.ai_text,
                       f"Запрос отправлен в «{label}».\n"
                       "Ждём ответ (работает на вашей подписке, без API-"
                       "биллинга)…")
        timeout = int(self.config.get("ai_timeout", 300))

        def work():
            res = self.ai.run(key, prompt, timeout=timeout)
            self._task_queue.put(("ai_done", res))

        threading.Thread(target=work, daemon=True).start()

    def _on_ai_done(self, res) -> None:
        self._busy(False)
        self.ai_btn.configure(state=tk.NORMAL)
        if res.ok:
            header = f"Ответ от «{self._label_for(res.backend)}»:\n" + "=" * 60 + "\n\n"
            self._set_text(self.ai_text, header + res.text)
            self._status("Ответ ИИ получен.")
        else:
            self._set_text(
                self.ai_text,
                f"Не удалось получить ответ от ИИ.\n\nПричина: {res.error}\n\n"
                "Проверьте, что CLI установлен, вы вошли в аккаунт, и при "
                "необходимости поправьте команду запуска в «Настройки ИИ».\n\n"
                "Как обходной путь — нажмите «Копировать промпт» и вставьте "
                "его в чат вручную.")
            self._status("Ошибка ответа ИИ.")

    def _label_for(self, key: str) -> str:
        b = self.ai.by_key(key)
        return b.label if b else key

    # -------------------------------------------------------------- Autofix
    def run_autofix(self) -> None:
        if not self._ensure_analysis():
            return
        plan = self.current_plan or remediation.build_plan(self.current_analysis)
        auto = remediation.auto_steps(plan)

        lines = ["Будут выполнены ТОЛЬКО безопасные, неразрушающие проверки:\n"]
        for s in auto:
            lines.append(f"  • {s.title}\n      {s.command}")
        lines.append("\nОни требуют прав администратора (появится запрос UAC) и "
                     "выполнятся в отдельном окне консоли.\n")
        lines.append("Остальные шаги плана (обновление драйверов, тест ОЗУ, "
                     "chkdsk /f /r и т.д.) смотрите на вкладке «Что делать» и "
                     "выполняйте осознанно.\n\nЗапустить безопасные проверки?")

        if not messagebox.askyesno("Autofix — безопасные проверки",
                                   "\n".join(lines)):
            return

        ok, msg = autofix_mod.run_safe_steps(auto)
        if ok:
            self._status("Autofix запущен — следите за окном консоли.")
            messagebox.showinfo("Autofix", msg)
        else:
            self._status("Autofix недоступен.")
            messagebox.showwarning("Autofix", msg)

    # ------------------------------------------------------------- settings
    def open_settings(self) -> None:
        SettingsDialog(self.root, self)

    # --------------------------------------------------------------- queue
    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self._task_queue.get_nowait()
                if kind == "analysis_done":
                    self._on_analysis_done(payload)
                elif kind == "analysis_error":
                    self._on_analysis_error(payload)
                elif kind == "ai_done":
                    self._on_ai_done(payload)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)


class SettingsDialog(tk.Toplevel):
    """Диалог настроек: cdb, таймаут ИИ, команды запуска ИИ."""

    def __init__(self, parent: tk.Tk, app: BSODAnalyzerApp):
        super().__init__(parent)
        self.app = app
        self.title("Настройки ИИ и анализа")
        self.geometry("720x560")
        self.transient(parent)
        self.grab_set()

        cfg = app.config
        pad = {"padx": 10, "pady": 4}

        frm = ttk.Frame(self, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        # cdb.
        self.use_cdb_var = tk.BooleanVar(value=bool(cfg.get("use_cdb", True)))
        ttk.Checkbutton(frm, text="Использовать cdb.exe для глубокого анализа "
                        "(!analyze -v)", variable=self.use_cdb_var).pack(
            anchor=tk.W, **pad)

        row = ttk.Frame(frm)
        row.pack(fill=tk.X, **pad)
        ttk.Label(row, text="Путь к cdb.exe (пусто = искать автоматически):").pack(
            side=tk.LEFT)
        self.cdb_var = tk.StringVar(value=cfg.get("cdb_path", ""))
        ttk.Entry(row, textvariable=self.cdb_var, width=40).pack(
            side=tk.LEFT, padx=6)
        ttk.Button(row, text="…", width=3, command=self._pick_cdb).pack(
            side=tk.LEFT)

        found = dump_parser.find_cdb()
        ttk.Label(frm, text=(f"Автопоиск нашёл: {found}" if found
                             else "Автопоиск: cdb.exe не найден. Установите "
                                  "Debugging Tools for Windows (Windows SDK)."),
                  foreground=("#166534" if found else "#9a3412")).pack(
            anchor=tk.W, **pad)

        row2 = ttk.Frame(frm)
        row2.pack(fill=tk.X, **pad)
        ttk.Label(row2, text="Таймаут ответа ИИ (сек):").pack(side=tk.LEFT)
        self.timeout_var = tk.IntVar(value=int(cfg.get("ai_timeout", 300)))
        ttk.Spinbox(row2, from_=30, to=1800, increment=30,
                    textvariable=self.timeout_var, width=8).pack(
            side=tk.LEFT, padx=6)

        ttk.Separator(frm).pack(fill=tk.X, pady=8)
        ttk.Label(frm, text="Команды запуска ИИ-CLI (плейсхолдеры: {exe}, "
                  "{prompt}).\nЕсли {prompt} нет — промпт подаётся в stdin.",
                  font=("", 9)).pack(anchor=tk.W, **pad)

        self.cmd_vars: Dict[str, tk.StringVar] = {}
        for b in app.ai.backends:
            if b.clipboard_only:
                continue
            r = ttk.Frame(frm)
            r.pack(fill=tk.X, **pad)
            avail = "✓" if b.is_available() else "✗ не найден"
            ttk.Label(r, text=f"{b.label} [{avail}]:", width=30).pack(
                side=tk.LEFT)
            var = tk.StringVar(value=b.command_template)
            ttk.Entry(r, textvariable=var, width=42).pack(
                side=tk.LEFT, padx=6, fill=tk.X, expand=True)
            self.cmd_vars[b.key] = var

        btns = ttk.Frame(frm)
        btns.pack(fill=tk.X, side=tk.BOTTOM, pady=(10, 0))
        ttk.Button(btns, text="Сохранить", command=self._save).pack(
            side=tk.RIGHT)
        ttk.Button(btns, text="Отмена", command=self.destroy).pack(
            side=tk.RIGHT, padx=6)

    def _pick_cdb(self) -> None:
        path = filedialog.askopenfilename(
            title="Выберите cdb.exe",
            filetypes=[("cdb.exe", "cdb.exe"), ("Все файлы", "*.*")])
        if path:
            self.cdb_var.set(path)

    def _save(self) -> None:
        cfg = self.app.config
        cfg["use_cdb"] = bool(self.use_cdb_var.get())
        cfg["cdb_path"] = self.cdb_var.get().strip()
        cfg["ai_timeout"] = int(self.timeout_var.get())
        overrides = cfg.setdefault("ai_backends", {})
        for key, var in self.cmd_vars.items():
            overrides.setdefault(key, {})["command_template"] = var.get().strip()
        config_mod.save_config(cfg)
        # Применяем к рантайму.
        self.app.ai = AIRunner(config_mod.backends_from_config(cfg))
        self.app._refresh_backend_combo()
        self.destroy()
        self.app._status("Настройки сохранены.")


def main() -> None:
    root = tk.Tk()
    BSODAnalyzerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

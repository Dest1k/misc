# -*- coding: utf-8 -*-
"""Tkinter GUI for the evidence-first BSOD analyzer."""

from __future__ import annotations

import queue
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import autofix as autofix_mod
from . import config as config_mod
from . import correlation, dump_finder, dump_parser, remediation, report
from .ai_backends import AIRunner
from .dump_finder import DumpFile
from .dump_parser import DumpAnalysis

APP_TITLE = "BSOD Dump Analyzer — доказательный анализ синих экранов"


class BSODAnalyzerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1220x780")
        self.root.minsize(980, 620)

        self.config = config_mod.load_config()
        self.ai: Optional[AIRunner] = None
        self.dumps: List[DumpFile] = []
        self.current_analysis: Optional[DumpAnalysis] = None
        self.current_plan: List[remediation.FixStep] = []
        self._task_queue: "queue.Queue[Tuple[str, object]]" = queue.Queue()
        self._backend_labels: Dict[str, str] = {}
        self._ai_runtime_enabled = False

        self._build_ui()
        self.set_ai_runtime_enabled(bool(self.config.get("ai_enabled", False)))
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
        ttk.Button(
            toolbar, text="🔄 Обновить список", command=self.refresh_dumps,
        ).pack(side=tk.LEFT)
        ttk.Button(
            toolbar, text="📁 Добавить папку…", command=self.add_folder,
        ).pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(
            toolbar, text="🗑 Удалить выбранные", command=self.delete_selected,
        ).pack(side=tk.LEFT, padx=(6, 0))
        self.correlate_btn = ttk.Button(
            toolbar, text="🔗 Корреляция серии", command=self.correlate_dumps,
        )
        self.correlate_btn.pack(side=tk.LEFT, padx=(6, 0))
        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(
            side=tk.LEFT, fill=tk.Y, padx=10,
        )
        ttk.Button(
            toolbar, text="⚙ Настройки…", command=self.open_settings,
        ).pack(side=tk.LEFT)

        main = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 6))
        self._build_dump_list(main)
        self._build_detail_panel(main)

        self.status_var = tk.StringVar(value="Готово.")
        status = ttk.Frame(self.root)
        status.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Separator(status).pack(fill=tk.X)
        self.progress = ttk.Progressbar(status, mode="indeterminate", length=140)
        self.progress.pack(side=tk.RIGHT, padx=8, pady=3)
        ttk.Label(status, textvariable=self.status_var, anchor=tk.W).pack(
            side=tk.LEFT, fill=tk.X, padx=8, pady=3,
        )

    def _build_dump_list(self, parent: ttk.PanedWindow) -> None:
        left = ttk.Frame(parent)
        parent.add(left, weight=1)
        ttk.Label(left, text="Найденные дампы:", font=("", 10, "bold")).pack(
            anchor=tk.W, pady=(0, 4),
        )

        columns = ("name", "date", "size", "kind")
        self.tree = ttk.Treeview(
            left, columns=columns, show="headings", selectmode="extended", height=18,
        )
        for column, title, width, anchor in (
            ("name", "Файл", 190, tk.W),
            ("date", "Дата", 135, tk.CENTER),
            ("size", "Размер", 75, tk.E),
            ("kind", "Тип", 155, tk.W),
        ):
            self.tree.heading(column, text=title)
            self.tree.column(column, width=width, anchor=anchor)
        scrollbar = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.LEFT, fill=tk.Y)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", lambda _event: self.analyze_selected())

    def _build_detail_panel(self, parent: ttk.PanedWindow) -> None:
        right = ttk.Frame(parent)
        parent.add(right, weight=2)

        actions = ttk.Frame(right)
        actions.pack(fill=tk.X, pady=(0, 6))
        self.analyze_btn = ttk.Button(
            actions, text="🔬 Анализировать", command=self.analyze_selected,
        )
        self.analyze_btn.pack(side=tk.LEFT)

        # This entire frame is absent from the layout while AI is disabled.
        self.ai_frame = ttk.Frame(actions)
        ttk.Label(self.ai_frame, text="ИИ (опционально):").pack(side=tk.LEFT)
        self.backend_var = tk.StringVar()
        self.backend_combo = ttk.Combobox(
            self.ai_frame,
            textvariable=self.backend_var,
            state="readonly",
            width=27,
        )
        self.backend_combo.pack(side=tk.LEFT, padx=(4, 0))
        self.ai_btn = ttk.Button(
            self.ai_frame, text="🤖 Второе мнение", command=self.analyze_with_ai,
        )
        self.ai_btn.pack(side=tk.LEFT, padx=(6, 0))
        self.copy_prompt_btn = ttk.Button(
            self.ai_frame, text="📋 Копировать промпт", command=self.copy_prompt,
        )
        self.copy_prompt_btn.pack(side=tk.LEFT, padx=(6, 0))

        self.autofix_btn = ttk.Button(
            actions, text="🛠 Безопасный Autofix", command=self.run_autofix,
        )
        self.autofix_btn.pack(side=tk.RIGHT)

        self.nb = ttk.Notebook(right)
        self.nb.pack(fill=tk.BOTH, expand=True)
        self.report_tab, self.report_text = self._create_text_tab("📄 Отчёт")
        self.tech_tab, self.tech_text = self._create_text_tab("🔧 Технические детали")
        self.plan_tab, self.plan_text = self._create_text_tab("🩺 Что делать")
        self.corr_tab, self.corr_text = self._create_text_tab("🔗 Корреляция")
        self.ai_tab, self.ai_text = self._create_text_tab(
            "🤖 Ответ ИИ", visible=False,
        )
        self._set_text(
            self.report_text,
            "Выберите один дамп слева и нажмите «Анализировать».\n\n"
            "Основной анализ выполняется локально. ИИ-функции выключены по умолчанию "
            "и появляются только после явного включения в настройках.",
        )

    def _create_text_tab(
        self, title: str, visible: bool = True,
    ) -> Tuple[ttk.Frame, tk.Text]:
        frame = ttk.Frame(self.nb)
        if visible:
            self.nb.add(frame, text=title)
        text = tk.Text(
            frame, wrap=tk.WORD, font=("Consolas", 10), padx=10, pady=8, undo=False,
        )
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text.yview)
        text.configure(yscrollcommand=scrollbar.set, state=tk.DISABLED)
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.LEFT, fill=tk.Y)
        return frame, text

    # ------------------------------------------------------------- helpers
    def _set_text(self, widget: tk.Text, content: str) -> None:
        widget.configure(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert("1.0", content)
        widget.configure(state=tk.DISABLED)

    def _status(self, message: str) -> None:
        self.status_var.set(message)

    def _busy(self, enabled: bool) -> None:
        if enabled:
            self.progress.start(12)
        else:
            self.progress.stop()

    def _selected_dumps(self) -> List[DumpFile]:
        selected: List[DumpFile] = []
        for item in self.tree.selection():
            try:
                index = int(item)
            except ValueError:
                continue
            if 0 <= index < len(self.dumps):
                selected.append(self.dumps[index])
        return selected

    def _tab_is_managed(self, tab: ttk.Frame) -> bool:
        return str(tab) in self.nb.tabs()

    # ------------------------------------------------------- optional AI UI
    def set_ai_runtime_enabled(self, enabled: bool) -> None:
        """Show/hide and initialize/deinitialize every AI surface at runtime."""
        enabled = bool(enabled)
        if enabled == self._ai_runtime_enabled:
            return
        self._ai_runtime_enabled = enabled
        if enabled:
            # CLI discovery only happens here, after explicit opt-in.
            self.ai = AIRunner(config_mod.backends_from_config(self.config))
            self._refresh_backend_combo()
            self.ai_frame.pack(side=tk.LEFT, padx=(12, 0))
            if not self._tab_is_managed(self.ai_tab):
                self.nb.add(self.ai_tab, text="🤖 Ответ ИИ")
            self._status("Опциональные ИИ-функции включены.")
        else:
            if self._tab_is_managed(self.ai_tab) and self.nb.select() == str(self.ai_tab):
                self.nb.select(self.report_tab)
            if self._tab_is_managed(self.ai_tab):
                self.nb.hide(self.ai_tab)
            self.ai_frame.pack_forget()
            self.backend_combo["values"] = []
            self.backend_var.set("")
            self._backend_labels = {}
            self.ai = None
            self._status("ИИ-функции выключены; работает только локальный анализ.")

    def _refresh_backend_combo(self) -> None:
        if self.ai is None:
            self.backend_combo["values"] = []
            self.backend_var.set("")
            self._backend_labels = {}
            return
        available = self.ai.available()
        labels = [backend.label for backend in available]
        self._backend_labels = {
            backend.label: backend.key for backend in available
        }
        self.backend_combo["values"] = labels
        if labels:
            if self.backend_var.get() not in labels:
                self.backend_var.set(labels[0])
        else:
            self.backend_var.set("")

    # -------------------------------------------------------------- actions
    def refresh_dumps(self) -> None:
        self._status("Поиск дампов…")
        extra = [Path(path) for path in self.config.get("extra_locations", [])]
        try:
            self.dumps = dump_finder.find_dumps(extra_locations=extra)
        except Exception as exc:  # GUI boundary: do not crash the event loop.
            messagebox.showerror("Ошибка", "Не удалось найти дампы:\n{}".format(exc))
            self.dumps = []

        self.tree.delete(*self.tree.get_children())
        for index, dump in enumerate(self.dumps):
            self.tree.insert(
                "", tk.END, iid=str(index),
                values=(dump.name, dump.mtime_str, dump.size_human, dump.kind_ru),
            )
        if self.dumps:
            self._status(
                "Найдено дампов: {}. Свежий: {}".format(
                    len(self.dumps), self.dumps[0].name,
                )
            )
        else:
            self._status(
                "Дампы не найдены. Это может означать отсутствие недавних сбоев "
                "или недостаточные права к системным каталогам."
            )

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
        names = "\n".join("  • " + dump.name for dump in selected)
        if not messagebox.askyesno(
            "Подтверждение удаления",
            "Безвозвратно удалить {} файл(ов)?\n\n{}".format(len(selected), names),
        ):
            return
        outcome = dump_finder.delete_dumps(selected)
        errors = [(dump, error) for dump, error in outcome if error]
        if errors:
            messagebox.showwarning(
                "Удалено с ошибками",
                "Некоторые файлы не удалены:\n\n{}".format(
                    "\n".join("{}: {}".format(dump.name, error) for dump, error in errors)
                ),
            )
        self.refresh_dumps()

    def _on_select(self, _event=None) -> None:
        selected = self._selected_dumps()
        if len(selected) == 1:
            self._status("Выбран: {} ({})".format(selected[0].name, selected[0].path))

    def analyze_selected(self) -> None:
        selected = self._selected_dumps()
        if len(selected) != 1:
            messagebox.showinfo("Анализ", "Выберите ровно один дамп для анализа.")
            return
        dump = selected[0]
        self._status("Анализ {}…".format(dump.name))
        self._busy(True)
        self.analyze_btn.configure(state=tk.DISABLED)
        use_cdb = bool(self.config.get("use_cdb", True))
        cdb_path = self.config.get("cdb_path") or None
        timeout = int(self.config.get("cdb_timeout", 240))

        def work() -> None:
            try:
                analysis = dump_parser.analyze(
                    dump.path,
                    use_cdb=use_cdb,
                    cdb_exe=cdb_path,
                    timeout=timeout,
                )
                self._task_queue.put(("analysis_done", analysis))
            except Exception as exc:
                self._task_queue.put(("analysis_error", str(exc)))

        threading.Thread(target=work, daemon=True).start()

    def correlate_dumps(self) -> None:
        """Разобрать все найденные дампы и показать корреляцию серии."""
        if len(self.dumps) < 2:
            messagebox.showinfo(
                "Корреляция серии",
                "Для корреляции нужно хотя бы два дампа. Повторяемость модуля по "
                "нескольким независимым падениям — более сильный сигнал, чем "
                "один дамп.")
            return
        dumps = list(self.dumps)
        self._status("Корреляция {} дампов…".format(len(dumps)))
        self._busy(True)
        self.correlate_btn.configure(state=tk.DISABLED)
        use_cdb = bool(self.config.get("use_cdb", True))
        cdb_path = self.config.get("cdb_path") or None
        timeout = int(self.config.get("cdb_timeout", 240))
        timestamps = {d.name: d.mtime_str for d in dumps}

        def work() -> None:
            analyses = []
            for d in dumps:
                try:
                    analyses.append(dump_parser.analyze(
                        d.path, use_cdb=use_cdb, cdb_exe=cdb_path,
                        timeout=timeout))
                except Exception:  # один битый дамп не должен рушить серию
                    continue
            report_obj = correlation.correlate(analyses, timestamps=timestamps)
            self._task_queue.put(("correlation_done", report_obj))

        threading.Thread(target=work, daemon=True).start()

    def _on_correlation_done(self, report_obj) -> None:
        self._busy(False)
        self.correlate_btn.configure(state=tk.NORMAL)
        self._set_text(self.corr_text, correlation.format_report(report_obj))
        self.nb.select(self.corr_tab)
        self._status("Корреляция завершена: проанализировано {} дампов.".format(
            report_obj.total))

    def _on_analysis_done(self, analysis: DumpAnalysis) -> None:
        self._busy(False)
        self.analyze_btn.configure(state=tk.NORMAL)
        self.current_analysis = analysis
        self._set_text(self.report_text, report.build_human_report(analysis))
        self._set_text(self.tech_text, self._build_tech_text(analysis))
        self.current_plan = remediation.build_plan(analysis)
        self._set_text(
            self.plan_text, remediation.format_plan(self.current_plan),
        )
        self.nb.select(self.report_tab)
        diagnosis = analysis.diagnosis
        category = getattr(diagnosis, "category", "unknown")
        cdb_note = "с WinDbg/CDB" if analysis.cdb_used else "без WinDbg/CDB"
        self._status(
            "Анализ завершён ({}, категория: {}): {}".format(
                cdb_note, category, analysis.path.name,
            )
        )

    def _build_tech_text(self, analysis: DumpAnalysis) -> str:
        lines = [
            "Файл: {}".format(analysis.path),
            "Формат дампа: {}".format(analysis.dump_format),
            "Архитектура: {}".format(analysis.arch or "н/д"),
        ]
        if analysis.bugcheck_code is not None:
            lines.append("Header bugcheck: {}".format(analysis.bugcheck_hex))
            for index, value in enumerate(analysis.bugcheck_params, start=1):
                lines.append("  Arg{}: 0x{:016X}".format(index, value))
        if analysis.cdb_bugcheck_code is not None:
            lines.append(
                "CDB .bugcheck: 0x{:08X}".format(
                    analysis.cdb_bugcheck_code & 0xFFFFFFFF,
                )
            )
            for index, value in enumerate(analysis.cdb_bugcheck_params, start=1):
                lines.append("  CDB Arg{}: 0x{:016X}".format(index, value))
        if analysis.exception_code is not None:
            lines.append("Exception code: 0x{:08X}".format(analysis.exception_code))

        for label, value in (
            ("Probably caused by", analysis.caused_by),
            ("IMAGE_NAME", analysis.image_name),
            ("MODULE_NAME", analysis.module_name),
            ("SYMBOL_NAME", analysis.symbol_name),
            ("PROCESS_NAME", analysis.process_name),
            ("FAILURE_BUCKET_ID", analysis.failure_bucket),
            ("FAILURE_ID_HASH", analysis.failure_hash),
        ):
            if value:
                lines.append("{}: {}".format(label, value))
        lines.append("Symbol status: {}".format(analysis.symbol_status))
        if analysis.symbol_warnings:
            lines.append("Symbol warnings:")
            lines.extend("  - " + warning for warning in analysis.symbol_warnings)
        if analysis.stack_modules:
            lines.append("Stack modules: {}".format(", ".join(analysis.stack_modules)))
        if analysis.driver_details:
            details = analysis.driver_details
            lines.extend(["", "lmvm metadata:"])
            for label, value in (
                ("Module", details.module),
                ("Image path", details.image_path),
                ("Image name", details.image_name),
                ("Timestamp", details.timestamp),
                ("Image size", details.image_size),
                ("File version", details.file_version),
                ("Product version", details.product_version),
                ("Company", details.company_name),
                ("Product", details.product_name),
                ("Description", details.file_description),
            ):
                if value:
                    lines.append("  {}: {}".format(label, value))

        lines.extend([
            "",
            "CDB command: {}".format(analysis.cdb_command or "не запускался"),
            "CDB exit code: {}".format(analysis.cdb_exit_code),
            "CDB timeout: {}".format(analysis.cdb_timed_out),
            "CDB duration: {}".format(
                "{:.2f} s".format(analysis.cdb_duration_seconds)
                if analysis.cdb_duration_seconds is not None else "н/д"
            ),
        ])
        if analysis.parse_error:
            lines.append("Parse note: {}".format(analysis.parse_error))
        if analysis.analysis_warnings:
            lines.append("Analysis warnings:")
            lines.extend("  - " + warning for warning in analysis.analysis_warnings)

        lines.extend(["", "=" * 72])
        if analysis.cdb_output:
            lines.extend(["ПОЛНЫЙ ВЫВОД WINDBG/CDB", "=" * 72, analysis.cdb_output])
        else:
            lines.append(
                "WinDbg/CDB не запускался. Для глубокого локального анализа установите "
                "Debugging Tools for Windows или укажите cdb.exe в настройках."
            )
        return "\n".join(lines)

    def _on_analysis_error(self, error: str) -> None:
        self._busy(False)
        self.analyze_btn.configure(state=tk.NORMAL)
        self._status("Ошибка анализа.")
        messagebox.showerror("Ошибка анализа", error)

    # ------------------------------------------------------------------ AI
    def _ensure_analysis(self) -> bool:
        if self.current_analysis is None:
            messagebox.showinfo(
                "Сначала анализ",
                "Сначала выполните локальный анализ выбранного дампа.",
            )
            return False
        return True

    def copy_prompt(self) -> None:
        if not self._ai_runtime_enabled:
            return
        if not self._ensure_analysis():
            return
        prompt = report.build_ai_prompt(self.current_analysis)
        self.root.clipboard_clear()
        self.root.clipboard_append(prompt)
        self._status("Промпт независимого второго мнения скопирован.")
        messagebox.showinfo(
            "Скопировано",
            "Промпт с локальным выводом и техническими фактами скопирован. "
            "ИИ предлагается проверить вывод, а не заменить локальный анализ.",
        )

    def analyze_with_ai(self) -> None:
        if not self._ai_runtime_enabled or self.ai is None:
            return
        if not self._ensure_analysis():
            return
        label = self.backend_var.get()
        key = self._backend_labels.get(label)
        if not key:
            messagebox.showinfo(
                "Нет доступного ИИ-CLI",
                "CLI не найден. Можно использовать кнопку копирования промпта.",
            )
            return
        backend = self.ai.by_key(key)
        if backend and backend.clipboard_only:
            self.copy_prompt()
            return

        prompt = report.build_ai_prompt(self.current_analysis)
        self._status("Запрос второго мнения: {}…".format(label))
        self._busy(True)
        self.ai_btn.configure(state=tk.DISABLED)
        self.nb.select(self.ai_tab)
        self._set_text(
            self.ai_text,
            "Запрос отправлен в «{}». Локальный диагноз уже сформирован; "
            "ожидается независимая рецензия.\n".format(label),
        )
        timeout = int(self.config.get("ai_timeout", 300))

        def work() -> None:
            assert self.ai is not None
            result = self.ai.run(key, prompt, timeout=timeout)
            self._task_queue.put(("ai_done", result))

        threading.Thread(target=work, daemon=True).start()

    def _on_ai_done(self, result) -> None:
        self._busy(False)
        self.ai_btn.configure(state=tk.NORMAL)
        if result.ok:
            self._set_text(
                self.ai_text,
                "Независимое второе мнение:\n{}\n\n{}".format("=" * 60, result.text),
            )
            self._status("Ответ ИИ получен.")
        else:
            self._set_text(
                self.ai_text,
                "Не удалось получить второе мнение.\n\nПричина: {}\n\n"
                "Локальный отчёт и план остаются полностью работоспособными."
                .format(result.error),
            )
            self._status("ИИ недоступен; локальный анализ сохранён.")

    # -------------------------------------------------------------- Autofix
    def run_autofix(self) -> None:
        if not self._ensure_analysis():
            return
        plan = self.current_plan or remediation.build_plan(self.current_analysis)
        automatic = remediation.auto_steps(plan)
        if not automatic:
            messagebox.showinfo(
                "Autofix",
                "Для этой категории нет разрешённых автоматических действий. "
                "Следуйте ручному плану на вкладке «Что делать».",
            )
            return

        lines = [
            "Будут выполнены только команды из встроенного allow-list:\n",
        ]
        for step in automatic:
            lines.append(
                "  • {}\n      риск: {}; команда: {}\n      проверка: {}"
                .format(
                    step.title,
                    step.risk,
                    step.command,
                    step.verify_command or "не требуется",
                )
            )
        lines.extend([
            "",
            "Для каждого шага сохраняются stdout, stderr, exit code, длительность "
            "и результат проверочной команды. JSON и текстовый отчёт останутся в "
            "%LOCALAPPDATA%\\BSODAnalyzer\\reports.",
            "",
            "Driver Verifier, DDU, удаление драйверов, BIOS/прошивки, chkdsk /f /r "
            "и операции загрузчика сюда попасть не могут.",
            "",
            "Запустить?",
        ])
        if not messagebox.askyesno(
            "Безопасный Autofix", "\n".join(lines),
        ):
            return
        ok, message = autofix_mod.run_safe_steps(automatic)
        if ok:
            self._status("Autofix запущен; результаты будут сохранены в отчёте.")
            messagebox.showinfo("Autofix", message)
        else:
            self._status("Autofix недоступен.")
            messagebox.showwarning("Autofix", message)

    # ------------------------------------------------------------- settings
    def open_settings(self) -> None:
        SettingsDialog(self.root, self)

    # --------------------------------------------------------------- queue
    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self._task_queue.get_nowait()
                if kind == "analysis_done":
                    self._on_analysis_done(payload)  # type: ignore[arg-type]
                elif kind == "analysis_error":
                    self._on_analysis_error(str(payload))
                elif kind == "correlation_done":
                    self._on_correlation_done(payload)
                elif kind == "ai_done":
                    self._on_ai_done(payload)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)


class SettingsDialog(tk.Toplevel):
    """Analysis settings plus an explicit, reversible AI opt-in."""

    def __init__(self, parent: tk.Tk, app: BSODAnalyzerApp):
        super().__init__(parent)
        self.app = app
        self._original_ai_enabled = bool(app.config.get("ai_enabled", False))
        self._saved = False
        self.title("Настройки анализа")
        self.geometry("780x610")
        self.minsize(680, 520)
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._cancel)

        outer = ttk.Frame(self, padding=10)
        outer.pack(fill=tk.BOTH, expand=True)
        notebook = ttk.Notebook(outer)
        notebook.pack(fill=tk.BOTH, expand=True)
        analysis_tab = ttk.Frame(notebook, padding=12)
        ai_tab = ttk.Frame(notebook, padding=12)
        notebook.add(analysis_tab, text="Локальный анализ")
        notebook.add(ai_tab, text="Опциональный ИИ")

        self._build_analysis_tab(analysis_tab)
        self._build_ai_tab(ai_tab)

        buttons = ttk.Frame(outer)
        buttons.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(buttons, text="Сохранить", command=self._save).pack(side=tk.RIGHT)
        ttk.Button(buttons, text="Отмена", command=self._cancel).pack(
            side=tk.RIGHT, padx=6,
        )

    def _build_analysis_tab(self, frame: ttk.Frame) -> None:
        cfg = self.app.config
        ttk.Label(
            frame,
            text="Основной анализ выполняется локально и не зависит от ИИ.",
            font=("", 10, "bold"),
        ).pack(anchor=tk.W, pady=(0, 10))

        self.use_cdb_var = tk.BooleanVar(value=bool(cfg.get("use_cdb", True)))
        ttk.Checkbutton(
            frame,
            text="Использовать cdb.exe / WinDbg для глубокого анализа",
            variable=self.use_cdb_var,
        ).pack(anchor=tk.W, pady=4)

        path_row = ttk.Frame(frame)
        path_row.pack(fill=tk.X, pady=6)
        ttk.Label(path_row, text="Путь к cdb.exe (пусто = автопоиск):").pack(side=tk.LEFT)
        self.cdb_var = tk.StringVar(value=cfg.get("cdb_path", ""))
        ttk.Entry(path_row, textvariable=self.cdb_var).pack(
            side=tk.LEFT, padx=6, fill=tk.X, expand=True,
        )
        ttk.Button(path_row, text="…", width=3, command=self._pick_cdb).pack(side=tk.LEFT)

        found = dump_parser.find_cdb()
        ttk.Label(
            frame,
            text=(
                "Автопоиск нашёл: {}".format(found)
                if found else
                "cdb.exe не найден. Установите Debugging Tools for Windows."
            ),
        ).pack(anchor=tk.W, pady=4)

        timeout_row = ttk.Frame(frame)
        timeout_row.pack(fill=tk.X, pady=8)
        ttk.Label(timeout_row, text="Таймаут WinDbg/CDB (сек):").pack(side=tk.LEFT)
        self.cdb_timeout_var = tk.IntVar(value=int(cfg.get("cdb_timeout", 240)))
        ttk.Spinbox(
            timeout_row, from_=30, to=1800, increment=30,
            textvariable=self.cdb_timeout_var, width=8,
        ).pack(side=tk.LEFT, padx=6)

        ttk.Separator(frame).pack(fill=tk.X, pady=12)
        ttk.Label(
            frame,
            text=(
                "Для максимальной точности используйте символы Microsoft и по возможности "
                "kernel/automatic memory dump. Оценка уверенности в отчёте — качество "
                "доказательств, а не выдуманная вероятность."
            ),
            wraplength=690,
            justify=tk.LEFT,
        ).pack(anchor=tk.W)

    def _build_ai_tab(self, frame: ttk.Frame) -> None:
        cfg = self.app.config
        self.ai_enabled_var = tk.BooleanVar(
            value=bool(cfg.get("ai_enabled", False)),
        )
        ttk.Checkbutton(
            frame,
            text="Включить опциональные ИИ-функции",
            variable=self.ai_enabled_var,
            command=self._preview_ai_toggle,
        ).pack(anchor=tk.W)
        ttk.Label(
            frame,
            text=(
                "По умолчанию выключено. При включении появляются кнопки и вкладка "
                "второго мнения, после выключения они снова исчезают. Локальный диагноз, "
                "план и Autofix от ИИ не зависят."
            ),
            wraplength=690,
            justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(6, 12))

        self.ai_options_frame = ttk.LabelFrame(
            frame, text="Параметры второго мнения", padding=10,
        )
        self.ai_options_frame.pack(fill=tk.BOTH, expand=True)

        timeout_row = ttk.Frame(self.ai_options_frame)
        timeout_row.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(timeout_row, text="Таймаут ответа (сек):").pack(side=tk.LEFT)
        self.ai_timeout_var = tk.IntVar(value=int(cfg.get("ai_timeout", 300)))
        self.ai_timeout_spin = ttk.Spinbox(
            timeout_row, from_=30, to=3600, increment=30,
            textvariable=self.ai_timeout_var, width=8,
        )
        self.ai_timeout_spin.pack(side=tk.LEFT, padx=6)

        ttk.Label(
            self.ai_options_frame,
            text="Команды CLI ({exe}, {prompt}; без {prompt} запрос идёт через stdin):",
        ).pack(anchor=tk.W, pady=(0, 4))
        self.cmd_vars: Dict[str, tk.StringVar] = {}
        self.command_entries: List[ttk.Entry] = []
        for backend in config_mod.backends_from_config(cfg):
            if backend.clipboard_only:
                continue
            row = ttk.Frame(self.ai_options_frame)
            row.pack(fill=tk.X, pady=3)
            ttk.Label(row, text=backend.label + ":", width=29).pack(side=tk.LEFT)
            variable = tk.StringVar(value=backend.command_template)
            entry = ttk.Entry(row, textvariable=variable)
            entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
            self.cmd_vars[backend.key] = variable
            self.command_entries.append(entry)
        self._update_ai_option_state()

    def _preview_ai_toggle(self) -> None:
        enabled = bool(self.ai_enabled_var.get())
        self._update_ai_option_state()
        self.app.set_ai_runtime_enabled(enabled)

    def _update_ai_option_state(self) -> None:
        state = "normal" if self.ai_enabled_var.get() else "disabled"
        self.ai_timeout_spin.configure(state=state)
        for entry in self.command_entries:
            entry.configure(state=state)

    def _pick_cdb(self) -> None:
        path = filedialog.askopenfilename(
            title="Выберите cdb.exe",
            filetypes=[("cdb.exe", "cdb.exe"), ("Все файлы", "*.*")],
        )
        if path:
            self.cdb_var.set(path)

    def _save(self) -> None:
        cfg = self.app.config
        cfg["use_cdb"] = bool(self.use_cdb_var.get())
        cfg["cdb_path"] = self.cdb_var.get().strip()
        cfg["cdb_timeout"] = int(self.cdb_timeout_var.get())
        cfg["ai_enabled"] = bool(self.ai_enabled_var.get())
        cfg["ai_timeout"] = int(self.ai_timeout_var.get())
        overrides = cfg.setdefault("ai_backends", {})
        for key, variable in self.cmd_vars.items():
            overrides.setdefault(key, {})["command_template"] = variable.get().strip()
        config_mod.save_config(cfg)
        self._saved = True
        self.app.set_ai_runtime_enabled(bool(cfg["ai_enabled"]))
        if self.app.ai is not None:
            self.app.ai = AIRunner(config_mod.backends_from_config(cfg))
            self.app._refresh_backend_combo()
        self.destroy()
        self.app._status("Настройки сохранены.")

    def _cancel(self) -> None:
        if not self._saved:
            self.app.set_ai_runtime_enabled(self._original_ai_enabled)
        self.destroy()


def main() -> None:
    root = tk.Tk()
    BSODAnalyzerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

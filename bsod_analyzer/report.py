# -*- coding: utf-8 -*-
"""Формирование человекочитаемого отчёта и промпта для ИИ из DumpAnalysis."""

from __future__ import annotations

from typing import List

from . import bugcheck_db
from .dump_parser import DumpAnalysis


def _bullet(lines: List[str], prefix: str = "  • ") -> str:
    return "\n".join(prefix + l for l in lines)


def build_human_report(a: DumpAnalysis) -> str:
    """Собрать понятный отчёт на русском по результатам разбора дампа."""
    out: List[str] = []
    out.append("=" * 66)
    out.append(f"ФАЙЛ ДАМПА: {a.path.name}")
    out.append(f"Путь: {a.path}")
    if a.arch:
        out.append(f"Архитектура: {a.arch}")
    out.append("=" * 66)
    out.append("")

    if a.parse_error and a.bugcheck_code is None and a.exception_code is None:
        out.append("⚠ Не удалось разобрать дамп автоматически.")
        out.append(f"   {a.parse_error}")
        out.append("")
        out.append("Это может быть дамп нестандартного формата. Попробуйте "
                   "анализ через cdb.exe или через ИИ (кнопки ниже).")
        return "\n".join(out)

    # --- Дамп ядра (BSOD) ---
    if a.bugcheck_code is not None:
        hexc = a.bugcheck_hex
        if a.bugcheck:
            out.append(f"❗ STOP-код: {hexc}  ({a.bugcheck.name})")
            out.append("")
            out.append("ЧТО ПРОИЗОШЛО:")
            out.append("  " + a.bugcheck.summary)
        else:
            out.append(f"❗ STOP-код: {hexc}  (нет описания в базе)")
            out.append("")
            out.append("ЧТО ПРОИЗОШЛО:")
            out.append("  Система аварийно остановилась (синий экран). Точное "
                       "описание этого кода не найдено в локальной базе — "
                       "рекомендуется анализ через ИИ.")
        out.append("")

        # Параметры + подсказки.
        if a.bugcheck_params:
            out.append("Параметры STOP-кода:")
            for i, p in enumerate(a.bugcheck_params, start=1):
                hint = ""
                if a.bugcheck and i in a.bugcheck.param_hints:
                    hint = f"  — {a.bugcheck.param_hints[i]}"
                out.append(f"  Параметр {i}: 0x{p:016X}{hint}")
            out.append("")
            # Для 0x7E/0x1E первый параметр — код исключения.
            if a.bugcheck and a.bugcheck.name.startswith(("SYSTEM_THREAD",
                                                          "KMODE_EXCEPTION")):
                exc = bugcheck_db.lookup_exception(a.bugcheck_params[0])
                if exc:
                    out.append(f"Расшифровка исключения (параметр 1): {exc}")
                    out.append("")

        if a.bugcheck:
            out.append("ВЕРОЯТНЫЕ ПРИЧИНЫ:")
            out.append(_bullet(a.bugcheck.common_causes))
            out.append("")
            out.append("КАК ИСПРАВИТЬ:")
            out.append(_bullet(a.bugcheck.fixes))
            out.append("")

    # --- User-mode дамп приложения ---
    elif a.exception_code is not None:
        out.append("Это дамп упавшего приложения (не синий экран).")
        exc = bugcheck_db.lookup_exception(a.exception_code)
        out.append(f"Код исключения: 0x{a.exception_code:08X}")
        if exc:
            out.append(f"  {exc}")
        out.append("")
        out.append("Такие сбои обычно относятся к конкретной программе, а не ко "
                   "всей системе. Обновите/переустановите приложение, обновите "
                   "видеодрайвер и .NET/Visual C++ Redistributable.")
        out.append("")

    # --- Данные из cdb ---
    if a.cdb_used:
        out.append("-" * 66)
        out.append("ГЛУБОКИЙ АНАЛИЗ (cdb / !analyze -v):")
        if a.probable_module:
            out.append(f"  ➤ Наиболее вероятный виновник: {a.probable_module}")
            drv = _driver_hint(a.probable_module)
            if drv:
                out.append(f"     {drv}")
        if a.process_name:
            out.append(f"  ➤ Процесс на момент сбоя: {a.process_name}")
        if a.failure_bucket:
            out.append(f"  ➤ Категория сбоя (bucket): {a.failure_bucket}")
        if not (a.probable_module or a.failure_bucket):
            out.append("  Точный виновник не выделен — см. полный вывод cdb во "
                       "вкладке «Технические детали».")
        out.append("")
    else:
        out.append("-" * 66)
        out.append("ℹ Глубокий анализ (cdb.exe) не выполнялся или инструмент не "
                   "найден.")
        out.append("  Для точного определения виновного драйвера установите "
                   "«Debugging Tools for Windows» (входят в Windows SDK) — "
                   "программа найдёт cdb.exe автоматически.")
        out.append("")

    out.append("СЛЕДУЮЩИЙ ШАГ:")
    out.append("  • Нажмите «Анализ через ИИ» для развёрнутого разбора живым "
               "языком с учётом именно ваших параметров.")
    out.append("  • Нажмите «Autofix», чтобы запустить безопасные проверки и "
               "получить план действий.")
    return "\n".join(out)


# Подсказки по известным файлам драйверов -> что это.
_KNOWN_DRIVERS = {
    "nvlddmkm.sys": "драйвер видеокарты NVIDIA — переустановите начисто (DDU) свежую версию.",
    "atikmdag.sys": "драйвер видеокарты AMD — переустановите начисто (DDU).",
    "amdkmdag.sys": "драйвер видеокарты AMD — переустановите начисто (DDU).",
    "igdkmd64.sys": "драйвер графики Intel — обновите с сайта Intel.",
    "ntoskrnl.exe": "ядро Windows: обычно это лишь «место падения», реальная причина — драйвер или ОЗУ.",
    "ntfs.sys": "драйвер файловой системы — проверьте диск (chkdsk) и SMART.",
    "wdf01000.sys": "инфраструктура драйверов Windows — виноват какой-то сторонний драйвер поверх неё.",
    "tcpip.sys": "сетевой стек — обновите драйвер сетевой карты/Wi-Fi, проверьте VPN/антивирус.",
    "ndis.sys": "сетевая подсистема — обновите сетевые драйверы.",
    "usbxhci.sys": "драйвер USB 3 — обновите драйвер USB-контроллера/чипсета.",
    "storahci.sys": "драйвер SATA/AHCI — обновите драйвер контроллера и прошивку SSD.",
    "iastorac.sys": "Intel RST — обновите драйвер Intel Rapid Storage.",
    "dxgkrnl.sys": "графическое ядро DirectX — почти всегда причина в драйвере видеокарты.",
    "dxgmms2.sys": "менеджер памяти DirectX — переустановите драйвер видеокарты.",
    "win32kbase.sys": "подсистема Win32 — часто связано с драйвером видеокарты.",
    "watchdog.sys": "сторож видеоподсистемы — обновите драйвер GPU.",
}


def _driver_hint(module: str) -> str:
    key = module.strip().lower()
    if not key.endswith((".sys", ".exe", ".dll")):
        key += ".sys"
    return _KNOWN_DRIVERS.get(key, "")


def build_ai_prompt(a: DumpAnalysis) -> str:
    """Составить подробный промпт для ИИ на основе технических данных."""
    lines: List[str] = []
    lines.append(
        "Ты — эксперт по диагностике синих экранов (BSOD) Windows. "
        "Проанализируй данные краш-дампа ниже и объясни ПРОСТЫМ живым языком "
        "для обычного пользователя: 1) что именно случилось; 2) наиболее "
        "вероятная причина именно по этим параметрам; 3) пошаговый план "
        "устранения от самого вероятного к менее вероятному; 4) какие команды "
        "или программы запустить. Отвечай по-русски, структурировано, без воды."
    )
    lines.append("")
    lines.append("=== ДАННЫЕ ДАМПА ===")
    lines.append(f"Файл: {a.path.name}")
    lines.append(f"Формат: {a.dump_format}; архитектура: {a.arch or 'н/д'}")

    if a.bugcheck_code is not None:
        name = a.bugcheck.name if a.bugcheck else "неизвестно"
        lines.append(f"STOP-код (bugcheck): {a.bugcheck_hex} ({name})")
        if a.bugcheck_params:
            for i, p in enumerate(a.bugcheck_params, start=1):
                lines.append(f"  Параметр {i}: 0x{p:016X}")
    if a.exception_code is not None:
        lines.append(f"Код исключения (user-mode): 0x{a.exception_code:08X}")
    if a.probable_module:
        lines.append(f"Вероятный виновный модуль (по cdb): {a.probable_module}")
    if a.process_name:
        lines.append(f"Процесс на момент сбоя: {a.process_name}")
    if a.failure_bucket:
        lines.append(f"Категория сбоя (bucket): {a.failure_bucket}")

    if a.cdb_output:
        # Урезаем вывод cdb, чтобы не раздувать промпт.
        snippet = a.cdb_output.strip()
        if len(snippet) > 6000:
            snippet = snippet[:6000] + "\n...[вывод обрезан]..."
        lines.append("")
        lines.append("=== ВЫВОД !analyze -v (фрагмент) ===")
        lines.append(snippet)

    return "\n".join(lines)

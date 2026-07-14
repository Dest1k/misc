# -*- coding: utf-8 -*-
"""Human-readable, evidence-first reports and optional AI prompts."""

from __future__ import annotations

from typing import List, Optional

from . import bugcheck_db
from .diagnosis import Diagnosis, diagnose
from .dump_parser import DumpAnalysis


def _bullet(lines: List[str], prefix: str = "  • ") -> str:
    return "\n".join(prefix + line for line in lines)


def _diagnosis(a: DumpAnalysis) -> Diagnosis:
    return a.diagnosis if isinstance(a.diagnosis, Diagnosis) else diagnose(a)


def build_human_report(a: DumpAnalysis) -> str:
    """Build a Russian report that labels facts, inference and uncertainty."""
    d = _diagnosis(a)
    out: List[str] = []
    out.extend([
        "=" * 72,
        "АНАЛИЗ ДАМПА: {}".format(a.path.name),
        "Путь: {}".format(a.path),
        "Формат: {}{}".format(
            a.dump_format,
            " / {}".format(a.arch) if a.arch else "",
        ),
        "=" * 72,
        "",
        "1. ЧТО ДОСТОВЕРНО ИЗВЛЕЧЕНО",
    ])

    if a.bugcheck_code is not None:
        name = a.bugcheck.name if a.bugcheck else "нет в локальном справочнике"
        out.append("  • STOP-код: {} ({})".format(a.bugcheck_hex, name))
        for index, value in enumerate(a.bugcheck_params, start=1):
            hint = ""
            if a.bugcheck and index in a.bugcheck.param_hints:
                hint = " — {}".format(a.bugcheck.param_hints[index])
            out.append(
                "  • Arg{}: 0x{:016X}{}".format(index, value, hint)
            )
    elif a.exception_code is not None:
        out.append("  • User-mode exception: 0x{:08X}".format(a.exception_code))
        exception = bugcheck_db.lookup_exception(a.exception_code)
        if exception:
            out.append("  • Расшифровка: {}".format(exception))
    else:
        out.append("  • STOP-код или исключение из файла не извлечены.")

    if a.cdb_used:
        out.append("  • WinDbg/CDB: выполнен")
        if a.process_name:
            out.append("  • Процесс в момент сбоя: {}".format(a.process_name))
        if a.failure_bucket:
            out.append("  • FAILURE_BUCKET_ID: {}".format(a.failure_bucket))
        if a.failure_hash:
            out.append("  • FAILURE_ID_HASH: {}".format(a.failure_hash))
        if a.symbol_name:
            out.append("  • SYMBOL_NAME: {}".format(a.symbol_name))
        if a.image_name:
            out.append("  • IMAGE_NAME: {}".format(a.image_name))
        if a.module_name:
            out.append("  • MODULE_NAME: {}".format(a.module_name))
        if a.caused_by:
            out.append(
                "  • Probably caused by: {} (это подсказка WinDbg, не доказательство)"
                .format(a.caused_by)
            )
        out.append("  • Качество символов: {}".format(_symbol_status_ru(a.symbol_status)))
    else:
        out.append("  • WinDbg/CDB не выполнялся или не найден.")

    if a.parse_error:
        out.append("  • Замечание парсера: {}".format(a.parse_error))

    out.extend([
        "",
        "2. ОСНОВНОЙ ВЫВОД",
        "  {}".format(d.title),
        "  {}".format(d.summary),
        "",
        "  Качество вывода: {}.".format(d.confidence_ru),
        "  Это оценка согласованности доказательств, а не статистическая вероятность.",
    ])
    if d.suspected_module:
        out.append("  Подозреваемый модуль: {}".format(d.suspected_module))
    else:
        out.append("  Конкретный виновный модуль не назначен.")

    out.extend(["", "3. ПОЧЕМУ СДЕЛАН ТАКОЙ ВЫВОД"])
    if d.evidence:
        for item in d.evidence:
            out.append("  • {}".format(item.text))
    else:
        out.append("  • Независимых технических признаков недостаточно.")

    out.extend(["", "4. ЧТО СНИЖАЕТ УВЕРЕННОСТЬ"])
    if d.confidence_reducers:
        out.append(_bullet(d.confidence_reducers))
    else:
        out.append("  • Существенных технических ограничений в доступном выводе не найдено.")

    out.extend(["", "5. АЛЬТЕРНАТИВНЫЕ ГИПОТЕЗЫ"])
    if d.alternatives:
        out.append(_bullet(d.alternatives))
    else:
        out.append("  • Значимые альтернативы не сформированы.")

    if d.background_causes:
        out.extend([
            "",
            "6. СПРАВОЧНЫЙ ФОН ПО STOP-КОДУ",
            "  Ниже — типичные причины такого кода вообще, а не диагноз этого ПК:",
            _bullet(d.background_causes),
        ])

    out.extend(["", "7. ОГРАНИЧЕНИЯ"])
    if d.limitations:
        out.append(_bullet(d.limitations))
    else:
        out.append("  • Дополнительные ограничения не зафиксированы.")

    out.extend([
        "",
        "СЛЕДУЮЩИЙ ШАГ",
        "  Откройте вкладку «Что делать»: план построен именно для категории «{}» "
        "и начинается со сбора/проверки доказательств, а не с ремонта наугад."
        .format(_category_ru(d.category)),
    ])
    return "\n".join(out)


def _symbol_status_ru(value: str) -> str:
    return {
        "good": "хорошее",
        "partial": "частичное",
        "poor": "плохое",
        "unknown": "не подтверждено",
    }.get(value or "unknown", value or "не подтверждено")


def _category_ru(value: str) -> str:
    return {
        "driver": "драйвер",
        "gpu": "графика",
        "storage": "накопитель/контроллер",
        "memory": "повреждение памяти",
        "hardware": "аппаратная нестабильность",
        "system_corruption": "компоненты Windows",
        "application": "приложение",
        "unknown": "не локализовано",
    }.get(value, value)


def build_ai_prompt(a: DumpAnalysis) -> str:
    """Build an optional second-opinion prompt without outsourcing the diagnosis."""
    d = _diagnosis(a)
    lines: List[str] = [
        "Ты выступаешь как независимый рецензент локального анализа BSOD Windows.",
        "Не повторяй вывод автоматически. Проверь его на контрпримеры, разделяй "
        "факты и гипотезы, не называй ntoskrnl/ntkrnlmp/hal/Wdf01000/ndis/tcpip "
        "корневой причиной без независимых доказательств.",
        "Ответь по-русски: (1) какие факты надёжны; (2) согласен ли ты с основной "
        "гипотезой; (3) какие альтернативы недооценены; (4) какие безопасные "
        "проверки дадут максимум информации; (5) какие действия нельзя автоматизировать.",
        "",
        "=== ЛОКАЛЬНЫЙ ВЫВОД ===",
        "Категория: {}".format(d.category),
        "Формулировка: {}".format(d.title),
        "Объяснение: {}".format(d.summary),
        "Качество: {} (не вероятность)".format(d.confidence),
        "Подозреваемый модуль: {}".format(d.suspected_module or "не назначен"),
        "",
        "=== ФАКТЫ ДАМПА ===",
        "Файл: {}".format(a.path.name),
        "Формат: {}; архитектура: {}".format(a.dump_format, a.arch or "н/д"),
    ]
    if a.bugcheck_code is not None:
        lines.append("STOP-код: {}".format(a.bugcheck_hex))
        for index, value in enumerate(a.bugcheck_params, start=1):
            lines.append("Arg{}: 0x{:016X}".format(index, value))
    if a.exception_code is not None:
        lines.append("Exception: 0x{:08X}".format(a.exception_code))
    for label, value in (
        ("Probably caused by", a.caused_by),
        ("IMAGE_NAME", a.image_name),
        ("MODULE_NAME", a.module_name),
        ("SYMBOL_NAME", a.symbol_name),
        ("PROCESS_NAME", a.process_name),
        ("FAILURE_BUCKET_ID", a.failure_bucket),
        ("FAILURE_ID_HASH", a.failure_hash),
    ):
        if value:
            lines.append("{}: {}".format(label, value))
    lines.append("Symbol status: {}".format(a.symbol_status))
    if a.symbol_warnings:
        lines.append("Symbol warnings: {}".format(" | ".join(a.symbol_warnings[:5])))

    if a.cdb_output:
        snippet = a.cdb_output.strip()
        if len(snippet) > 12000:
            snippet = snippet[:12000] + "\n...[вывод обрезан]..."
        lines.extend(["", "=== ВЫВОД WINDBG/CDB ===", snippet])
    return "\n".join(lines)

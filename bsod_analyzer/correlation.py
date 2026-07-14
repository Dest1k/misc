# -*- coding: utf-8 -*-
"""Корреляция серии дампов.

Один дамп показывает одно падение: случайный модуль в коротком стеке — слабый
сигнал. Если же один и тот же сторонний модуль повторяется в нескольких
НЕЗАВИСИМЫХ падениях, это заметно сильнее. Здесь мы аккуратно агрегируем уже
разобранные дампы, но НЕ превращаем счётчик повторений в вероятность —
калиброванной модели для этого нет.

Модуль сознательно исключает системные посредники (ntoskrnl, hal и т.п.) из
списка «повторяющихся виновников», оставляя их лишь как сигнал категории.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from .diagnosis import SYSTEM_PROXY_MODULES, normalize_module
from .dump_parser import DumpAnalysis


@dataclass
class ModuleRecurrence:
    module: str
    dump_count: int                       # в скольких РАЗНЫХ дампах встретился
    as_suspect_count: int                 # в скольких стал подозреваемым
    dumps: List[str] = field(default_factory=list)


@dataclass
class CorrelationReport:
    total: int
    bugcheck_distribution: Dict[str, int] = field(default_factory=dict)
    recurring_modules: List[ModuleRecurrence] = field(default_factory=list)
    bucket_groups: Dict[str, List[str]] = field(default_factory=dict)
    dominant_bugcheck: Optional[str] = None
    time_span: Optional[Tuple[str, str]] = None


def _third_party_modules(a: DumpAnalysis) -> Dict[str, bool]:
    """Собрать нормализованные сторонние модули дампа.

    Возвращает {module: is_suspect}. Системные посредники исключаются.
    """
    result: Dict[str, bool] = {}
    diagnosis = getattr(a, "diagnosis", None)
    suspect = normalize_module(getattr(diagnosis, "suspected_module", None))

    sources = [a.caused_by, a.image_name, a.module_name]
    if a.symbol_name:
        sources.append(a.symbol_name.split("!", 1)[0])
    sources.extend(a.stack_modules or [])

    for raw in sources:
        module = normalize_module(raw)
        if not module or module in SYSTEM_PROXY_MODULES:
            continue
        is_suspect = module == suspect
        result[module] = result.get(module, False) or is_suspect
    return result


def _bugcheck_label(a: DumpAnalysis) -> Optional[str]:
    if a.bugcheck_code is None:
        return None
    name = a.bugcheck.name if a.bugcheck else "неизвестный STOP-код"
    return "{} ({})".format(a.bugcheck_hex, name)


def correlate(analyses: Iterable[DumpAnalysis],
              timestamps: Optional[Dict[str, str]] = None) -> CorrelationReport:
    """Скоррелировать список уже разобранных дампов."""
    items = list(analyses)
    report = CorrelationReport(total=len(items))
    if not items:
        return report

    module_dumps: Dict[str, List[str]] = {}
    module_suspect: Dict[str, int] = {}

    for a in items:
        label = _bugcheck_label(a)
        if label:
            report.bugcheck_distribution[label] = \
                report.bugcheck_distribution.get(label, 0) + 1

        bucket = a.failure_bucket or a.failure_hash
        if bucket:
            report.bucket_groups.setdefault(bucket, []).append(a.path.name)

        for module, is_suspect in _third_party_modules(a).items():
            module_dumps.setdefault(module, []).append(a.path.name)
            if is_suspect:
                module_suspect[module] = module_suspect.get(module, 0) + 1

    recurring = [
        ModuleRecurrence(
            module=module,
            dump_count=len(set(names)),
            as_suspect_count=module_suspect.get(module, 0),
            dumps=sorted(set(names)),
        )
        for module, names in module_dumps.items()
    ]
    # Сильнее тот, кто повторяется в большем числе дампов и чаще был подозреваемым.
    recurring.sort(key=lambda r: (r.dump_count, r.as_suspect_count), reverse=True)
    report.recurring_modules = recurring

    if report.bugcheck_distribution:
        report.dominant_bugcheck = max(
            report.bugcheck_distribution.items(), key=lambda kv: kv[1])[0]

    if timestamps:
        times = sorted(t for name, t in timestamps.items()
                       if name in {a.path.name for a in items})
        if times:
            report.time_span = (times[0], times[-1])

    return report


def format_report(report: CorrelationReport) -> str:
    """Человекочитаемое представление корреляции серии дампов."""
    if report.total == 0:
        return "Нет дампов для корреляции."
    out: List[str] = []
    out.append("=" * 72)
    out.append("КОРРЕЛЯЦИЯ СЕРИИ ДАМПОВ")
    out.append("Проанализировано дампов: {}".format(report.total))
    if report.time_span:
        out.append("Период: {} — {}".format(*report.time_span))
    out.append("=" * 72)

    out.append("")
    out.append("1. РАСПРЕДЕЛЕНИЕ STOP-КОДОВ")
    if report.bugcheck_distribution:
        for label, count in sorted(report.bugcheck_distribution.items(),
                                   key=lambda kv: kv[1], reverse=True):
            out.append("  • {} — {} дамп(ов)".format(label, count))
        if report.dominant_bugcheck and len(report.bugcheck_distribution) == 1:
            out.append("  Все падения имеют один STOP-код — это само по себе "
                       "сигнал общей причины.")
    else:
        out.append("  • STOP-коды не извлечены.")

    out.append("")
    out.append("2. ПОВТОРЯЮЩИЕСЯ СТОРОННИЕ МОДУЛИ")
    strong = [r for r in report.recurring_modules if r.dump_count >= 2]
    if strong:
        out.append("  Повторение в нескольких независимых падениях усиливает "
                   "подозрение (но это не вероятность):")
        for r in strong:
            suspect = (", как подозреваемый: {}".format(r.as_suspect_count)
                       if r.as_suspect_count else "")
            out.append("  • {} — в {} из {} дампов{}".format(
                r.module, r.dump_count, report.total, suspect))
            out.append("      дампы: {}".format(", ".join(r.dumps)))
    elif report.recurring_modules:
        out.append("  Сторонние модули встречаются, но ни один не повторяется "
                   "более чем в одном дампе — устойчивого паттерна пока нет.")
    else:
        out.append("  Сторонние модули не выделены (нет данных WinDbg/CDB или "
                   "во всех дампах только системные компоненты).")

    if report.bucket_groups:
        out.append("")
        out.append("3. ГРУППЫ ПО FAILURE_BUCKET_ID / FAILURE_ID_HASH")
        for bucket, names in sorted(report.bucket_groups.items(),
                                    key=lambda kv: len(kv[1]), reverse=True):
            out.append("  • {}: {} дамп(ов) — {}".format(
                bucket, len(names), ", ".join(sorted(set(names)))))

    out.append("")
    out.append("ВЫВОД")
    if strong:
        top = strong[0]
        out.append("  Наиболее устойчивый признак — модуль {} (в {} из {} "
                   "падений). С него разумно начать проверку драйвера по плану "
                   "«Что делать».".format(top.module, top.dump_count,
                                          report.total))
    else:
        out.append("  Устойчивого повторяющегося виновника по серии не видно. "
                   "Ориентируйтесь на распределение STOP-кодов и включите "
                   "WinDbg/CDB для более богатых признаков.")
    return "\n".join(out)

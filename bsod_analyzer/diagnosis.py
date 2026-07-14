# -*- coding: utf-8 -*-
"""Evidence-based BSOD diagnosis.

This module deliberately separates *facts* extracted from a dump from
hypotheses inferred from those facts.  It never treats a single WinDbg label
as proof and it avoids presenting common Windows proxy modules as a concrete
root cause.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .dump_parser import DumpAnalysis


# Modules that frequently appear at the crash site while merely transporting
# or detecting corruption caused elsewhere.  They can still be useful category
# signals, but must not be named as a concrete culprit without stronger proof.
SYSTEM_PROXY_MODULES: Set[str] = {
    "ntoskrnl.exe",
    "ntkrnlmp.exe",
    "ntkrnlpa.exe",
    "hal.dll",
    "wdf01000.sys",
    "ndis.sys",
    "tcpip.sys",
    "storport.sys",
    "stornvme.sys",
    "ntfs.sys",
    "dxgkrnl.sys",
    "dxgmms2.sys",
    "win32kbase.sys",
    "memory_corruption",
    "hardware_ram",
    "unknown_image",
}

_MICROSOFT_COMPANY_MARKERS = (
    "microsoft",
    "windows",
)

_GPU_MODULES = {
    "nvlddmkm.sys",       # NVIDIA
    "amdkmdag.sys",       # AMD
    "atikmdag.sys",       # older AMD/ATI
    "igdkmd64.sys",       # Intel
    "igdkmdn64.sys",
    "igfxdkm.sys",
}

_STORAGE_MODULES = {
    "storahci.sys",
    "iastorac.sys",
    "iaStorAVC.sys".lower(),
    "stornvme.sys",
    "storport.sys",
    "ntfs.sys",
    "volmgr.sys",
    "disk.sys",
}

_NETWORK_MODULES = {
    "ndis.sys",
    "tcpip.sys",
    "netio.sys",
    "fwpkclnt.sys",
}

_MEMORY_CODES = {0x1A, 0x50, 0x12B, 0x109, 0x139}
_HARDWARE_CODES = {0x124, 0x9C, 0x101, 0x7F}
_STORAGE_CODES = {0x7A, 0xF4, 0xEF}
_GPU_CODES = {0x116, 0x117, 0xEA, 0x10E, 0x113}
_SYSTEM_CORRUPTION_CODES = {0xC000021A}
_DRIVER_CODES = {
    0x0A, 0x1E, 0x3B, 0x4A, 0x7E, 0x9F, 0xBE, 0xC2, 0xC4, 0xC5,
    0xCA, 0xD1, 0xD5, 0xFC, 0x133, 0x144,
}

_MODULE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


@dataclass(frozen=True)
class Evidence:
    """One independently identifiable observation."""

    source: str
    text: str
    weight: int = 0
    module: Optional[str] = None


@dataclass
class Diagnosis:
    """Human-facing interpretation of one dump.

    ``confidence`` is a quality grade, not a statistical probability.
    ``score`` is internal ranking support and should not be rendered with a
    percent sign.
    """

    category: str
    title: str
    summary: str
    confidence: str
    score: int
    suspected_module: Optional[str] = None
    evidence: List[Evidence] = field(default_factory=list)
    confidence_reducers: List[str] = field(default_factory=list)
    alternatives: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    background_causes: List[str] = field(default_factory=list)

    @property
    def confidence_ru(self) -> str:
        return {
            "high": "высокая",
            "medium": "средняя",
            "low": "низкая",
            "very_low": "очень низкая",
        }.get(self.confidence, self.confidence)


@dataclass
class _Candidate:
    module: str
    score: int = 0
    sources: Set[str] = field(default_factory=set)
    evidence: List[Evidence] = field(default_factory=list)


def normalize_module(value: Optional[str]) -> Optional[str]:
    """Normalize a debugger module token without accepting command syntax."""
    if not value:
        return None
    token = value.strip().strip("[](){}<>,:;\"'")
    token = token.split("+", 1)[0].split("!", 1)[0]
    token = token.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    if not token or not _MODULE_TOKEN_RE.fullmatch(token):
        return None
    lowered = token.lower()
    if "." not in lowered and lowered not in {
            "memory_corruption", "hardware_ram", "unknown_image"}:
        # WinDbg MODULE_NAME commonly omits the .sys suffix.
        lowered += ".sys"
    return lowered


def is_system_proxy(module: Optional[str]) -> bool:
    normalized = normalize_module(module)
    return bool(normalized and normalized in SYSTEM_PROXY_MODULES)


def is_safe_module_token(module: Optional[str]) -> bool:
    """Whether a module can safely be placed into a debugger command.

    This is intentionally stricter than ordinary display validation.  The
    caller must still pass the token as part of a fixed command, never through
    a shell.
    """
    if not module:
        return False
    raw = module.strip()
    return bool(_MODULE_TOKEN_RE.fullmatch(raw))


def _driver_is_microsoft(a: DumpAnalysis) -> bool:
    details = getattr(a, "driver_details", None)
    company = (getattr(details, "company_name", None) or "").lower()
    return any(marker in company for marker in _MICROSOFT_COMPANY_MARKERS)


def _add_candidate(
    candidates: Dict[str, _Candidate],
    raw_module: Optional[str],
    source: str,
    text: str,
    weight: int,
) -> None:
    module = normalize_module(raw_module)
    if not module:
        return
    candidate = candidates.setdefault(module, _Candidate(module=module))
    # A repeated parser field is not independent evidence.  Score a source only
    # once, but keep useful prose for the report.
    if source not in candidate.sources:
        candidate.score += weight
        candidate.sources.add(source)
        candidate.evidence.append(Evidence(source, text, weight, module))


def _candidate_table(a: DumpAnalysis) -> Dict[str, _Candidate]:
    candidates: Dict[str, _Candidate] = {}

    _add_candidate(
        candidates, getattr(a, "caused_by", None), "probably_caused_by",
        "WinDbg указал модуль в строке Probably caused by.", 22,
    )
    _add_candidate(
        candidates, getattr(a, "image_name", None) or a.probable_module,
        "image_name", "IMAGE_NAME указывает на этот образ.", 18,
    )
    _add_candidate(
        candidates, getattr(a, "module_name", None), "module_name",
        "MODULE_NAME совпадает с этим модулем.", 16,
    )
    symbol = getattr(a, "symbol_name", None)
    if symbol:
        _add_candidate(
            candidates, symbol.split("!", 1)[0], "symbol_name",
            "Символ сбойной инструкции относится к этому модулю.", 14,
        )

    counts: Dict[str, int] = {}
    for raw in getattr(a, "stack_modules", []) or []:
        module = normalize_module(raw)
        if module:
            counts[module] = counts.get(module, 0) + 1
    for module, count in counts.items():
        weight = 13 if count >= 2 else 6
        _add_candidate(
            candidates, module, "stack",
            "Модуль встречается в стеке {} раз(а).".format(count), weight,
        )

    bucket = (a.failure_bucket or "").lower()
    for module in list(candidates):
        stem = module.rsplit(".", 1)[0]
        if module in bucket or stem in bucket:
            _add_candidate(
                candidates, module, "failure_bucket",
                "Имя модуля присутствует в FAILURE_BUCKET_ID.", 9,
            )

    details = getattr(a, "driver_details", None)
    details_module = normalize_module(getattr(details, "module", None))
    if details_module:
        _add_candidate(
            candidates, details_module, "lmvm",
            "WinDbg смог получить метаданные образа через lmvm.", 7,
        )
        company = (getattr(details, "company_name", None) or "").lower()
        if company and not any(x in company for x in _MICROSOFT_COMPANY_MARKERS):
            _add_candidate(
                candidates, details_module, "third_party_metadata",
                "Метаданные образа указывают на стороннего производителя.", 10,
            )

    # Proxy modules retain category value but cannot win a culprit ranking from
    # ordinary debugger labels.
    for module, candidate in candidates.items():
        if module in SYSTEM_PROXY_MODULES:
            candidate.score -= 35
    return candidates


def _category_for(a: DumpAnalysis, module: Optional[str]) -> str:
    code = (a.bugcheck_code or 0) & 0xFFFFFFFF
    normalized = normalize_module(module)

    # Exact module names only.  Substring matching such as "nv" used to turn
    # NVMe storage drivers into false NVIDIA diagnoses.
    if normalized in _GPU_MODULES or code in _GPU_CODES:
        return "gpu"
    if normalized in _STORAGE_MODULES or code in _STORAGE_CODES:
        return "storage"
    if code in _HARDWARE_CODES:
        return "hardware"
    if code in _MEMORY_CODES:
        return "memory"
    if code in _SYSTEM_CORRUPTION_CODES:
        return "system_corruption"
    if normalized and normalized not in SYSTEM_PROXY_MODULES:
        return "driver"
    if code in _DRIVER_CODES:
        return "driver"
    if a.dump_format == "userdump":
        return "application"
    return "unknown"


def _category_summary(category: str, module: Optional[str]) -> Tuple[str, str]:
    if category == "gpu":
        if module and module not in SYSTEM_PROXY_MODULES:
            return (
                "Вероятный сбой графического драйвера",
                "Согласованные признаки ведут к графическому драйверу {}. ".format(module)
                + "Это ещё не доказывает аппаратную неисправность видеокарты.",
            )
        return (
            "Сбой в графической подсистеме",
            "STOP-код и стек относятся к графическому тракту, но конкретный "
            "сторонний драйвер пока не подтверждён.",
        )
    if category == "storage":
        if module and module not in SYSTEM_PROXY_MODULES:
            return (
                "Вероятный сбой драйвера или тракта хранения данных",
                "Несколько признаков указывают на {} и подсистему хранения."
                .format(module),
            )
        return (
            "Сбой в подсистеме хранения данных",
            "Дамп связан с диском, контроллером или файловой системой, но не "
            "позволяет пока выбрать один компонент.",
        )
    if category == "hardware":
        return (
            "Вероятная аппаратная нестабильность",
            "STOP-код относится к аппаратным ошибкам. Для локализации нужны "
            "WHEA-запись, параметры разгона, температуры и последовательные тесты.",
        )
    if category == "memory":
        return (
            "Обнаружено повреждение памяти",
            "Это факт о повреждённом состоянии памяти, но не доказательство "
            "физически неисправной ОЗУ: причиной также может быть драйвер, DMA, "
            "разгон или накопитель.",
        )
    if category == "system_corruption":
        return (
            "Вероятно повреждение компонентов Windows",
            "Собранные признаки делают проверку хранилища компонентов и системных "
            "файлов обоснованным следующим шагом.",
        )
    if category == "driver":
        if module and module not in SYSTEM_PROXY_MODULES:
            return (
                "Вероятный сбой стороннего драйвера",
                "Независимые сигналы дампа сходятся на модуле {}.".format(module),
            )
        return (
            "Вероятен драйверный сбой, виновник не доказан",
            "Характер STOP-кода типичен для драйвера, однако дамп не содержит "
            "достаточно независимых сигналов для безопасного назначения виновника.",
        )
    if category == "application":
        return (
            "Сбой пользовательского приложения",
            "Это user-mode дамп: проблема относится прежде всего к конкретному "
            "процессу, а не к аварийной остановке ядра Windows.",
        )
    return (
        "Причина пока не локализована",
        "Доступных данных недостаточно для честного выбора одной причины. Следующий "
        "шаг — улучшить качество дампа и собрать коррелирующие системные факты.",
    )


def _confidence(score: int, independent_sources: int, reducers: Sequence[str]) -> str:
    adjusted = score - min(30, len(reducers) * 7)
    if independent_sources >= 4 and adjusted >= 58:
        return "high"
    if independent_sources >= 2 and adjusted >= 34:
        return "medium"
    if independent_sources >= 1 and adjusted >= 14:
        return "low"
    return "very_low"


def _confidence_reducers(a: DumpAnalysis, best: Optional[_Candidate]) -> List[str]:
    reducers: List[str] = []
    if not a.cdb_used:
        reducers.append("Глубокий анализ WinDbg/CDB не выполнялся.")
    if getattr(a, "cdb_timed_out", False):
        reducers.append("Сеанс отладчика завершился по таймауту; вывод может быть неполным.")
    if getattr(a, "cdb_exit_code", 0) not in (None, 0):
        reducers.append("Отладчик завершился с ненулевым кодом возврата.")
    symbol_status = (getattr(a, "symbol_status", "unknown") or "unknown").lower()
    if symbol_status == "poor":
        reducers.append("Символы загружены плохо; имена функций и модулей могут быть неточными.")
    elif symbol_status in ("unknown", "partial"):
        reducers.append("Качество символов не подтверждено полностью.")
    if a.dump_format in ("kernel64", "kernel32") and not getattr(a, "stack_modules", None):
        reducers.append("В извлечённом выводе нет пригодного стека вызовов.")
    if getattr(a, "bugcheck_mismatch", False):
        reducers.append("STOP-код/параметры в заголовке и выводе отладчика расходятся.")
    if best and best.module in SYSTEM_PROXY_MODULES:
        reducers.append("Ведущий модуль является системным посредником, а не доказанным источником сбоя.")
    if best and len(best.sources) == 1:
        reducers.append("Модуль упомянут только одним источником; независимого подтверждения нет.")
    return reducers


def _alternatives(a: DumpAnalysis, category: str, suspected: Optional[str]) -> List[str]:
    alternatives: List[str] = []
    code = (a.bugcheck_code or 0) & 0xFFFFFFFF
    if category in ("driver", "gpu"):
        alternatives.extend([
            "Повреждение данных драйвером, который исчез из короткого minidump-стека.",
            "Нестабильная ОЗУ/XMP, исказившая код или структуры драйвера.",
        ])
    elif category == "memory":
        alternatives.extend([
            "Сторонний драйвер записал по неверному адресу.",
            "Нестабильный XMP/EXPO или контроллер памяти.",
            "Физическая ошибка одного из модулей ОЗУ.",
        ])
    elif category == "storage":
        alternatives.extend([
            "Драйвер/прошивка контроллера или накопителя.",
            "Потеря питания, кабель или аппаратная деградация накопителя.",
            "Повреждение файловой системы как следствие внезапного сбоя.",
        ])
    elif category == "hardware":
        alternatives.extend([
            "Разгон, undervolt или нестабильный профиль памяти.",
            "Перегрев или проблема питания.",
            "CPU, RAM, материнская плата или другое устройство, указанное WHEA-записью.",
        ])
    elif category == "unknown":
        alternatives.extend([
            "Сторонний драйвер, не попавший в доступный стек.",
            "Аппаратная нестабильность или разгон.",
            "Повреждение системных компонентов либо накопителя.",
        ])
    if suspected:
        alternatives = [x for x in alternatives if suspected.lower() not in x.lower()]
    if code == 0x124 and "WHEA" not in " ".join(alternatives):
        alternatives.insert(0, "Конкретный аппаратный источник нужно определить по WHEA_ERROR_RECORD.")
    return alternatives[:4]


def diagnose(a: DumpAnalysis) -> Diagnosis:
    """Build a conservative diagnosis from independently extracted signals."""
    candidates = _candidate_table(a)
    ordered = sorted(candidates.values(), key=lambda c: (c.score, len(c.sources)), reverse=True)
    best = ordered[0] if ordered else None

    suspected: Optional[str] = None
    score = best.score if best else 0
    independent = len(best.sources) if best else 0

    # One debugger label is a lead, not a culprit.  A proxy is never promoted.
    if best and best.module not in SYSTEM_PROXY_MODULES and independent >= 2 and score >= 30:
        suspected = best.module

    category = _category_for(a, suspected or (best.module if best else None))
    title, summary = _category_summary(category, suspected)
    reducers = _confidence_reducers(a, best)
    confidence = _confidence(score, independent, reducers)

    # Category-only diagnoses must not inherit a high grade from a proxy.
    if suspected is None and confidence in ("high", "medium"):
        confidence = "low"

    evidence: List[Evidence] = []
    if best:
        evidence.extend(best.evidence)
    if a.bugcheck_code is not None:
        name = a.bugcheck.name if a.bugcheck else "неизвестный STOP-код"
        evidence.insert(0, Evidence(
            "bugcheck",
            "Зафиксирован {} ({}), параметры: {}.".format(
                a.bugcheck_hex,
                name,
                ", ".join("0x{:X}".format(x) for x in a.bugcheck_params) or "нет",
            ),
            0,
        ))
    if a.failure_bucket:
        evidence.append(Evidence(
            "failure_bucket", "FAILURE_BUCKET_ID: {}.".format(a.failure_bucket), 0,
        ))
    if getattr(a, "failure_hash", None):
        evidence.append(Evidence(
            "failure_hash", "FAILURE_ID_HASH: {}.".format(a.failure_hash), 0,
        ))

    limitations: List[str] = []
    if a.dump_format in ("kernel64", "kernel32"):
        limitations.append(
            "Один дамп показывает одно падение; повторяемость по серии дампов пока не учтена."
        )
    if not a.cdb_used:
        limitations.append(
            "Без WinDbg/CDB доступны только заголовок и локальная база STOP-кодов."
        )
    if a.parse_error:
        limitations.append("Парсер сообщил: {}".format(a.parse_error))
    limitations.extend(getattr(a, "analysis_warnings", []) or [])

    background: List[str] = []
    if a.bugcheck:
        background = list(a.bugcheck.common_causes)

    return Diagnosis(
        category=category,
        title=title,
        summary=summary,
        confidence=confidence,
        score=max(0, score),
        suspected_module=suspected,
        evidence=evidence,
        confidence_reducers=reducers,
        alternatives=_alternatives(a, category, suspected),
        limitations=_unique(limitations),
        background_causes=_unique(background),
    )


def _unique(values: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    result: List[str] = []
    for value in values:
        value = (value or "").strip()
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result

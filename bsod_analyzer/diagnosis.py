# -*- coding: utf-8 -*-
"""Evidence-based diagnosis over parsed dump and debugger output.

The confidence score measures evidence quality and agreement.  It is not a
statistical probability that a component is defective.
"""
from __future__ import annotations

import ntpath
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .dump_parser import DumpAnalysis, normalize_bugcheck_code


SYSTEM_PROXIES = {
    "ntoskrnl", "ntoskrnl.exe", "ntkrnlmp", "ntkrnlmp.exe", "hal", "hal.dll",
    "memory_corruption", "hardware", "unknown_image", "nt",
    "genuineintel", "authenticamd", "whea", "whea.sys", "pshed", "pshed.dll",
    "intelppm", "intelppm.sys", "amdppm", "amdppm.sys",
    "mcupdate_genuineintel", "mcupdate_authenticamd",
    "wdf01000", "wdf01000.sys", "ndis", "ndis.sys", "tcpip", "tcpip.sys",
    "storport", "storport.sys", "stornvme", "stornvme.sys", "storahci", "storahci.sys",
    "dxgkrnl", "dxgkrnl.sys", "dxgmms2", "dxgmms2.sys", "win32kbase", "win32kbase.sys",
    "fltmgr", "fltmgr.sys", "ntfs", "ntfs.sys", "volmgr", "volmgr.sys",
    "partmgr", "partmgr.sys", "classpnp", "classpnp.sys", "disk", "disk.sys",
    "ci", "ci.dll", "pci", "pci.sys", "acpi", "acpi.sys",
    "usbhub", "usbhub.sys", "usbhub3", "usbhub3.sys", "usbxhci", "usbxhci.sys",
    "usbccgp", "usbccgp.sys", "hidusb", "hidusb.sys", "hidclass", "hidclass.sys",
    "kbdclass", "kbdclass.sys", "mouclass", "mouclass.sys",
    "netio", "netio.sys", "fwpkclnt", "fwpkclnt.sys", "afd", "afd.sys",
    "watchdog", "watchdog.sys", "basicdisplay", "basicdisplay.sys",
}

GPU_PREFIXES = (
    "nvlddmkm", "amdkmdag", "atikmdag", "igdkmd", "igfx",
    "amdxx", "atikmpag", "nvidia",
)
STORAGE_PREFIXES = (
    "iastor", "iaahci", "stornvme", "storahci", "spaceport", "samsung",
    "wdcsam", "wdnvme", "nvme", "vmd", "rcraid", "amdsata",
)
NETWORK_PREFIXES = ("netwtw", "rtwl", "rt640", "e1d", "e2f", "killer", "tap", "wireguard", "ndisrd")
SECURITY_PREFIXES = (
    "avp", "avast", "avg", "avira", "asw", "klif", "kaspersky", "sophos",
    "crowd", "csagent", "sentinel", "mbam", "carbonblack", "epf", "edr",
)

MEMORY_CODES = {0x1A, 0x50, 0x12B, 0x109}
HARDWARE_CODES = {0x124, 0x9C, 0x101, 0x7F}
STORAGE_CODES = {0x77, 0x7A}
GPU_CODES = {0x116, 0x113, 0x10E, 0xEA}
DRIVER_CODES = {0x0A, 0x18, 0x19, 0x1E, 0x3B, 0x4A, 0x9F, 0xBE, 0xC2, 0xC4,
                0xC5, 0xCA, 0xD1, 0xD5, 0xFC, 0x7E, 0x133, 0x139, 0x144}
SYSTEM_CODES = {0xEF, 0xF4}


@dataclass(frozen=True)
class Evidence:
    source: str
    detail: str
    weight: int
    module: Optional[str] = None

    @property
    def text(self) -> str:
        return self.detail


@dataclass(frozen=True)
class Alternative:
    title: str
    reason: str


@dataclass
class Diagnosis:
    category: str
    title: str
    summary: str
    culprit: Optional[str]
    confidence_score: int
    confidence_label: str
    facts: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    caveats: List[str] = field(default_factory=list)
    alternatives: List[Alternative] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    @property
    def culprit_module(self) -> Optional[str]:
        return self.culprit


@dataclass
class _Candidate:
    display: str
    score: int = 0
    sources: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)


_CAUSAL_GROUP_CAPS = {
    "attribution": 45,
    "stack": 28,
    "device-stack": 24,
}


def _source_group(source: str) -> Optional[str]:
    # !analyze fields such as Probably caused by / IMAGE_NAME / MODULE_NAME /
    # SYMBOL_NAME / FAILURE_BUCKET_ID are correlated products of one analysis
    # pass. Agreement inside that group is useful, but it is not independence.
    if source in {
        "Probably caused by", "IMAGE_NAME", "MODULE_NAME", "SYMBOL_NAME",
        "FAULTING_MODULE", "FAILURE_BUCKET_ID",
    }:
        return "attribution"
    if source == "STACK_TEXT":
        return "stack"
    if source == "DEVICE_STACK":
        return "device-stack"
    return None


def _grouped_candidate_score(candidate: _Candidate) -> Tuple[int, List[str]]:
    grouped: Dict[str, List[Evidence]] = {}
    has_lmvm = False
    for evidence in candidate.evidence:
        group = _source_group(evidence.source)
        if group:
            grouped.setdefault(group, []).append(evidence)
        elif evidence.source == "lmvm":
            has_lmvm = True

    group_scores: Dict[str, int] = {}
    for group, evidence_items in grouped.items():
        strongest = max(item.weight for item in evidence_items)
        consistency_bonus = 0
        if group == "attribution":
            # Several matching labels make the attribution cleaner, but the cap
            # prevents them from masquerading as independent observations.
            distinct_sources = len({item.source for item in evidence_items})
            consistency_bonus = min(12, max(0, distinct_sources - 1) * 3)
        group_scores[group] = min(
            _CAUSAL_GROUP_CAPS[group], strongest + consistency_bonus
        )

    groups = sorted(group_scores)
    score = sum(group_scores.values())
    if len(groups) > 1:
        score += min(16, 8 * (len(groups) - 1))
    # lmvm validates identity/version only; it never creates a causal group.
    if has_lmvm and groups:
        score += 4
    return min(90, score), groups


def _candidate_supported(score: int, groups: List[str]) -> bool:
    causal = set(groups)
    # A concrete name requires at least two different evidence classes.
    # Attribution + raw stack is the usual path; stack + device stack is also
    # acceptable for power/PnP dumps when !analyze omits a verdict.
    independent_shape = (
        "attribution" in causal and bool(causal & {"stack", "device-stack"})
    ) or ({"stack", "device-stack"} <= causal)
    return independent_shape and score >= 48


def _module_key(value: Optional[str]) -> str:
    if not value:
        return ""
    value = value.strip().strip("[],:;")
    if "!" in value:
        value = value.split("!", 1)[0]
    value = value.split("+", 1)[0]
    value = ntpath.basename(value).lower()
    return re.sub(r"\.(sys|dll|exe)$", "", value, flags=re.I)


def _base_key(value: Optional[str]) -> str:
    key = _module_key(value)
    return re.sub(r"\.(sys|dll|exe)$", "", key, flags=re.I)


def _display_module(value: str) -> str:
    cleaned = value.strip().strip("[],:;")
    if "!" in cleaned:
        cleaned = cleaned.split("!", 1)[0]
    if "+" in cleaned:
        cleaned = cleaned.split("+", 1)[0]
    return ntpath.basename(cleaned)


def is_system_proxy(value: Optional[str]) -> bool:
    key = _module_key(value)
    return key in SYSTEM_PROXIES or _base_key(value) in SYSTEM_PROXIES


def _module_category(value: Optional[str]) -> str:
    key = _base_key(value)
    if key.startswith(GPU_PREFIXES):
        return "gpu"
    if key.startswith(STORAGE_PREFIXES):
        return "storage"
    if key.startswith(NETWORK_PREFIXES):
        return "network"
    if key.startswith(SECURITY_PREFIXES):
        return "security"
    return "driver"


def _proxy_category(value: Optional[str]) -> str:
    key = _base_key(value)
    if key in {"dxgkrnl", "dxgmms2", "win32kbase"}:
        return "gpu"
    if key in {"storport", "stornvme", "storahci"}:
        return "storage"
    if key in {"ndis", "tcpip"}:
        return "network"
    if key in {"whea", "pshed", "intelppm", "amdppm", "genuineintel", "authenticamd"}:
        return "hardware"
    return "driver"


def _bugcheck_category(code: Optional[int]) -> str:
    low = normalize_bugcheck_code(code or 0)
    if low in HARDWARE_CODES:
        return "hardware"
    if low in GPU_CODES:
        return "gpu"
    if low in STORAGE_CODES:
        return "storage"
    if low in MEMORY_CODES:
        return "memory"
    if low in SYSTEM_CODES:
        return "system"
    if low in DRIVER_CODES:
        return "driver"
    return "unknown"


def _add_candidate(candidates: Dict[str, _Candidate], raw: Optional[str], source: str,
                   weight: int, detail: str) -> Optional[Evidence]:
    key = _module_key(raw)
    if not key:
        return None
    display = _display_module(raw or key)
    evidence = Evidence(source, detail, weight, display)
    candidate = candidates.setdefault(key, _Candidate(display=display))
    candidate.score += weight
    if source not in candidate.sources:
        candidate.sources.append(source)
    candidate.evidence.append(evidence)
    return evidence


def _build_facts(a: DumpAnalysis) -> List[str]:
    facts = ["Формат: {0}; архитектура: {1}.".format(a.dump_format, a.arch or "не определена")]
    if a.bugcheck_code is not None:
        name = a.bugcheck.name if a.bugcheck else "неизвестное имя"
        facts.append("STOP-код {0} ({1}).".format(a.bugcheck_hex, name))
        if a.bugcheck_params:
            facts.append("Параметры: {0}.".format(
                ", ".join("Arg{0}=0x{1:X}".format(index + 1, value)
                          for index, value in enumerate(a.bugcheck_params))
            ))
    if a.exception_code is not None:
        facts.append("Исключение user-mode: 0x{0:08X}.".format(a.exception_code))
    if a.process_name:
        facts.append("Процесс в момент сбоя: {0}.".format(a.process_name))
    if a.failure_bucket:
        facts.append("Failure bucket: {0}.".format(a.failure_bucket))
    if a.failure_hash:
        facts.append("Failure hash: {0}.".format(a.failure_hash))
    if a.cdb_used:
        facts.append("CDB/WinDbg выполнен{0}.".format(
            " с таймаутом и неполным выводом" if a.cdb_timed_out else ""
        ))
    elif a.cdb_error:
        facts.append("CDB/WinDbg был найден, но запустить его не удалось.")
    else:
        facts.append("Глубокий анализ CDB/WinDbg не выполнялся.")
    return facts


def _candidate_evidence(a: DumpAnalysis) -> Tuple[Dict[str, _Candidate], List[Evidence]]:
    candidates: Dict[str, _Candidate] = {}
    all_evidence: List[Evidence] = []
    inputs = [
        (a.probably_caused_by, "Probably caused by", 34,
         "WinDbg явно вывел «Probably caused by: {0}»."),
        (a.image_name, "IMAGE_NAME", 20, "IMAGE_NAME указывает на {0}."),
        (a.module_name, "MODULE_NAME", 16, "MODULE_NAME указывает на {0}."),
        (a.faulting_module, "FAULTING_MODULE", 18, "FAULTING_MODULE указывает на {0}."),
    ]
    for raw, source, weight, template in inputs:
        if raw:
            evidence = _add_candidate(candidates, raw, source, weight, template.format(_display_module(raw)))
            if evidence:
                all_evidence.append(evidence)
    if a.symbol_name:
        symbol_module = a.symbol_name.split("!", 1)[0]
        evidence = _add_candidate(
            candidates, symbol_module, "SYMBOL_NAME", 20,
            "SYMBOL_NAME разрешён как {0}.".format(a.symbol_name),
        )
        if evidence:
            all_evidence.append(evidence)

    counts = Counter(_module_key(item) for item in a.stack_modules if _module_key(item))
    for key, count in counts.items():
        weight = min(28, 7 * count)
        detail = "Модуль {0} встречается в разобранном стеке {1} раз(а).".format(key, count)
        evidence = _add_candidate(candidates, key, "STACK_TEXT", weight, detail)
        if evidence:
            all_evidence.append(evidence)

    device_counts = Counter(
        _module_key(item) for item in a.device_stack_drivers if _module_key(item)
    )
    for key, count in device_counts.items():
        # Parser intentionally de-duplicates driver objects, so one presence
        # already represents the device-stack evidence class.
        weight = 16
        detail = "Драйвер {0} присутствует в IRP/PnP device stack {1} раз(а).".format(key, count)
        evidence = _add_candidate(candidates, key, "DEVICE_STACK", weight, detail)
        if evidence:
            all_evidence.append(evidence)

    bucket_low = (a.failure_bucket or "").lower()
    for key in list(candidates):
        base = re.sub(r"\.(sys|dll|exe)$", "", key)
        pattern = r"(?:^|[^a-z0-9]){0}(?:\.(?:sys|dll|exe))?(?:$|[^a-z0-9])".format(
            re.escape(base)
        )
        if base and re.search(pattern, bucket_low, re.I):
            evidence = _add_candidate(
                candidates, key, "FAILURE_BUCKET_ID", 12,
                "Имя {0} повторяется в failure bucket.".format(key),
            )
            if evidence:
                all_evidence.append(evidence)

    detail_module = (
        a.lmvm_module or a.probably_caused_by or a.image_name
        or a.module_name or a.faulting_module
    )
    if detail_module and any((a.driver_path, a.driver_file_version, a.driver_company, a.driver_product)):
        detail = "Для {0} получены сведения lmvm".format(_display_module(detail_module))
        bits = [x for x in (a.driver_company, a.driver_file_version, a.driver_timestamp) if x]
        if bits:
            detail += ": " + "; ".join(bits)
        detail += "."
        evidence = _add_candidate(candidates, detail_module, "lmvm", 8, detail)
        if evidence:
            all_evidence.append(evidence)
    return candidates, all_evidence


def _confidence_label(score: int) -> str:
    if score >= 75:
        return "высокая"
    if score >= 50:
        return "средняя"
    if score >= 25:
        return "низкая"
    return "недостаточно данных"


def _alternatives(a: DumpAnalysis, category: str, culprit: Optional[str]) -> List[Alternative]:
    result: List[Alternative] = []
    code = normalize_bugcheck_code(a.bugcheck_code or 0)
    if category in {"driver", "gpu", "network", "storage", "security"}:
        result.append(Alternative(
            "Повреждение памяти, проявившееся в драйвере",
            "Один сбой драйвера не исключает RAM/XMP; нужна повторяемость или отдельный тест памяти.",
        ))
    if category == "memory" or code in MEMORY_CODES:
        result.extend([
            Alternative("Сторонний драйвер повредил память раньше",
                        "Memory Manager часто обнаруживает последствия, а не место первичного повреждения."),
            Alternative("Нестабильный XMP/EXPO или контроллер памяти",
                        "Особенно вероятно после изменения частот, таймингов или BIOS."),
        ])
    if category == "hardware":
        result.extend([
            Alternative("Питание или перегрев", "WHEA/CPU timeout не всегда означает физически сломанный CPU."),
            Alternative("Разгон или прошивка BIOS", "Нестабильные напряжения и микрокод могут имитировать дефект."),
        ])
    if category == "storage":
        result.append(Alternative("Контроллер/драйвер хранения, а не сам SSD",
                                  "I/O-ошибка может возникнуть в драйвере, кабеле, питании или прошивке."))
    if not culprit and category == "unknown":
        result.append(Alternative("Недостаточный тип дампа",
                                  "Мини-дамп может не содержать историю, нужную для локализации первичного повреждения."))
    return result[:4]


def diagnose(a: DumpAnalysis) -> Diagnosis:
    facts = _build_facts(a)
    candidates, all_evidence = _candidate_evidence(a)
    caveats: List[str] = []
    limitations: List[str] = []

    bug_category = _bugcheck_category(a.bugcheck_code)
    metrics: List[Tuple[bool, int, int, _Candidate, List[str]]] = []
    proxy_metrics: List[Tuple[int, int, _Candidate, List[str]]] = []
    for item in candidates.values():
        grouped_score, groups = _grouped_candidate_score(item)
        if is_system_proxy(item.display):
            proxy_metrics.append((grouped_score, item.score, item, groups))
            continue
        supported = _candidate_supported(grouped_score, groups)
        metrics.append((supported, grouped_score, item.score, item, groups))

    # Prefer a genuinely supported candidate over a louder but internally
    # correlated set of labels. Raw weight is only the final tie-breaker.
    metrics.sort(key=lambda value: (value[0], value[1], value[2]), reverse=True)
    proxy_metrics.sort(key=lambda value: (value[0], value[1]), reverse=True)
    selected: Optional[_Candidate] = metrics[0][3] if metrics else None
    grouped_score = metrics[0][1] if metrics else 0
    source_groups: List[str] = metrics[0][4] if metrics else []
    candidate_supported = metrics[0][0] if metrics else False
    proxy_candidate: Optional[_Candidate] = proxy_metrics[0][2] if proxy_metrics else None

    # If lmvm identifies the matching candidate as a Microsoft/in-box module,
    # keep it as a framework/proxy signal rather than a concrete root cause.
    selected_key = _module_key(selected.display) if selected else ""
    lmvm_key = _module_key(a.lmvm_module)
    if (
        selected and a.driver_company and "microsoft" in a.driver_company.lower()
        and lmvm_key and lmvm_key == selected_key
    ):
        proxy_candidate = selected
        selected = None
        grouped_score = 0
        source_groups = []
        candidate_supported = False
        caveats.append(
            "lmvm относит кандидат к Microsoft/in-box компонентам; он оставлен системным посредником, а не назван первопричиной."
        )

    culprit = selected.display if selected and candidate_supported else None
    category = _module_category(culprit) if culprit else bug_category
    if not culprit and proxy_candidate and bug_category in {"driver", "unknown"}:
        proxy_category = _proxy_category(proxy_candidate.display)
        if proxy_category != "driver":
            category = proxy_category
    if category == "driver" and bug_category in {"gpu", "storage"}:
        category = bug_category

    score = 0
    relevant_evidence: List[Evidence] = []
    if selected:
        score = grouped_score if candidate_supported else min(44, grouped_score)
        relevant_evidence = selected.evidence
        if len(source_groups) < 2:
            caveats.append("Конкретный модуль не подтверждён двумя различными группами сигналов.")
        elif grouped_score < 48:
            caveats.append("Группы сигналов согласуются, но их суммарное качество слишком низкое для назначения виновника.")
        if not candidate_supported:
            caveats.append(
                "Сигнал о модуле {0} недостаточно независим, поэтому он не назначен виновником.".format(
                    selected.display
                )
            )
    elif proxy_candidate:
        proxy_score, _proxy_groups = _grouped_candidate_score(proxy_candidate)
        score = min(35, proxy_score // 2)
        relevant_evidence = proxy_candidate.evidence
        caveats.append(
            "Отладчик указывает на системный модуль {0}; это обычно место проявления, а не доказанный виновник.".format(
                proxy_candidate.display
            )
        )
    elif bug_category != "unknown":
        score = 38
        caveats.append("Категория выведена из STOP-кода, но конкретный компонент не локализован.")

    code = normalize_bugcheck_code(a.bugcheck_code or 0)
    if bug_category == "hardware" and culprit:
        caveats.append(
            "Модуль {0} присутствует в отладочных метках, но для аппаратного STOP-кода этого недостаточно: "
            "он может быть наблюдателем ошибки, а не её источником.".format(culprit)
        )
        culprit = None
        category = "hardware"
        score = min(score, 45)
    if code == 0x124:
        # The command stream itself contains a WHEA section marker; require
        # fields that can only come from an actual decoded error record.
        whea_decoded = bool(
            a.cdb_output and re.search(
                r"(?:Error Source|Error Type|Error Severity|WHEA_ERROR_RECORD)",
                a.cdb_output, re.I,
            )
        )
        if whea_decoded:
            score = max(score, 58)
        else:
            caveats.append("Для WHEA не получена расшифровка !errrec; источник аппаратной ошибки не определён.")
    if a.symbol_quality == "poor":
        score -= 22
        caveats.append("Символы загружены плохо; имена модулей и стек могут быть неточными.")
    elif a.symbol_quality == "partial":
        score -= 8
        caveats.append("Часть символов неполна или содержит предупреждения.")
    elif a.symbols_reliable is False:
        score -= 18
        caveats.append("Отладчик сообщил о ненадёжных symbols.")
    elif a.symbol_quality == "unknown" and a.cdb_used:
        score -= 5
        caveats.append("Качество символов не удалось подтвердить по выводу отладчика.")
    if not a.cdb_used:
        score -= 22
        limitations.append("Без CDB/WinDbg доступны только заголовок дампа и локальная база STOP-кодов.")
    if a.cdb_timed_out:
        score -= 15
        limitations.append("CDB превысил таймаут; технический вывод неполон.")
    if a.cdb_error:
        limitations.append(a.cdb_error)
    if a.cdb_used and a.cdb_exit_code not in (None, 0):
        score -= 6
        caveats.append("CDB завершился с кодом {0}; часть расширенных команд могла не выполниться.".format(
            a.cdb_exit_code
        ))
    if a.header_cdb_mismatch:
        score -= 25
        caveats.append(
            a.header_cdb_mismatch_detail
            or "Заголовок и отладчик сообщили несовместимые данные bugcheck; вывод нельзя считать надёжным."
        )
    if a.parse_error:
        score -= 10
        limitations.append(a.parse_error)
    if a.dump_format == "userdump" and a.bugcheck_code is None:
        category = "application"
        if a.exception_code is not None:
            score = max(score, 45)
        limitations.append("Это дамп приложения, а не BSOD ядра.")
    score = max(0, min(95, score))
    # Even a nominally supported candidate is suppressed after severe quality
    # penalties (bad symbols, timeout, conflicting bugcheck data).
    if culprit and score < 35:
        caveats.append(
            "Кандидат {0} скрыт как конкретный виновник: итоговое качество доказательств слишком низкое.".format(
                culprit
            )
        )
        culprit = None
        category = bug_category

    if culprit:
        title = "Наиболее согласованная гипотеза: {0}".format(culprit)
        summary = (
            "Несколько групп извлечённых сигналов сходятся на модуле {0}. "
            "Это рабочая гипотеза для проверки, а не доказательство физической неисправности устройства."
        ).format(culprit)
    elif category == "hardware":
        title = "Аппаратная категория подтверждается STOP-кодом, компонент не локализован"
        summary = "Дамп указывает на аппаратный класс сбоя, но без достаточной расшифровки нельзя назвать CPU, RAM, питание или плату."
    elif category == "memory":
        title = "Обнаружено повреждение памяти, первопричина не установлена"
        summary = "Повреждение памяти может быть вызвано RAM/XMP, драйвером, DMA или уже испорченным состоянием ядра."
    elif category == "application":
        title = "Сбой пользовательского приложения"
        summary = "Дамп содержит исключение процесса; диагностика относится к приложению, а не к BSOD системы."
    elif category != "unknown":
        title = "Определена категория «{0}», но не конкретный виновник".format(category)
        summary = "STOP-код задаёт направление проверки, однако независимых сигналов для назначения модуля недостаточно."
    else:
        title = "Недостаточно данных для локализации причины"
        summary = "Дамп не дал согласованного набора свидетельств. Нужен полный вывод отладчика, другой тип дампа или серия сбоев."

    if a.symbol_warnings:
        limitations.extend(a.symbol_warnings[:4])
    limitations.extend(item for item in a.debugger_warnings[:4] if item not in limitations)

    return Diagnosis(
        category=category,
        title=title,
        summary=summary,
        culprit=culprit,
        confidence_score=score,
        confidence_label=_confidence_label(score),
        facts=facts,
        evidence=relevant_evidence or all_evidence[:6],
        caveats=caveats,
        alternatives=_alternatives(a, category, culprit),
        limitations=limitations,
    )


def build_diagnosis(a: DumpAnalysis) -> Diagnosis:
    """Compatibility alias used by earlier review branches."""
    return diagnose(a)

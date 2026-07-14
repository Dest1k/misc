# -*- coding: utf-8 -*-
"""Рекомендации и безопасный Autofix для устранения причин BSOD.

Философия безопасности:
  * Ничего не выполняется без явного подтверждения пользователя.
  * В автоматический прогон попадают только НЕразрушающие проверки
    (sfc, DISM, chkdsk в режиме сканирования, планирование диагностики ОЗУ,
    очистка старых дампов).
  * Потенциально рискованные действия (откат/удаление драйверов, Driver
    Verifier, chkdsk /f /r) выдаются как рекомендация с пояснением — их
    пользователь запускает осознанно.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .dump_parser import DumpAnalysis


@dataclass
class FixStep:
    title: str                 # что делает
    command: Optional[str]     # команда (None — ручное действие)
    explanation: str           # зачем
    needs_admin: bool = True
    safe_auto: bool = False    # можно ли включать в автоматический прогон
    needs_reboot: bool = False


# --- Универсальные безопасные шаги (подходят почти для любого BSOD) ---

def _base_safe_steps() -> List[FixStep]:
    return [
        FixStep(
            "Проверка целостности системных файлов (SFC)",
            "sfc /scannow",
            "Ищет и восстанавливает повреждённые системные файлы Windows. "
            "Полностью безопасно.",
            safe_auto=True,
        ),
        FixStep(
            "Восстановление образа системы (DISM)",
            "DISM /Online /Cleanup-Image /RestoreHealth",
            "Чинит хранилище компонентов Windows, из которого SFC берёт "
            "эталонные файлы. Безопасно, требует интернет.",
            safe_auto=True,
        ),
        FixStep(
            "Проверка диска в режиме сканирования",
            "chkdsk C: /scan",
            "Онлайн-проверка файловой системы без блокировки диска и без "
            "перезагрузки. Безопасно.",
            safe_auto=True,
        ),
        FixStep(
            "Проверка обновлений Windows",
            "start ms-settings:windowsupdate",
            "Свежие обновления часто содержат исправления драйверов и ядра.",
            needs_admin=False,
            safe_auto=False,
        ),
    ]


# --- Дополнительные шаги по категории причины ---

def _memory_steps() -> List[FixStep]:
    return [
        FixStep(
            "Запланировать диагностику памяти Windows",
            "mdsched.exe",
            "Откроет средство проверки ОЗУ. Тест выполнится при следующей "
            "перезагрузке. Для надёжности лучше MemTest86 (несколько проходов).",
            needs_admin=False,
        ),
        FixStep(
            "Отключить разгон/XMP памяти (вручную)",
            None,
            "Зайдите в BIOS/UEFI и верните память на стандартную частоту "
            "(отключите XMP/EXPO). Нестабильный XMP — частая причина сбоев ОЗУ.",
            needs_admin=False,
        ),
    ]


def _driver_steps(module: Optional[str]) -> List[FixStep]:
    steps: List[FixStep] = []
    if module:
        steps.append(FixStep(
            f"Обновить/переустановить драйвер: {module}",
            None,
            f"Анализ указывает на модуль {module}. Обновите соответствующий "
            f"драйвер с сайта производителя устройства; если сбой начался "
            f"после недавнего обновления — откатите драйвер в Диспетчере "
            f"устройств.",
            needs_admin=False,
        ))
    steps.append(FixStep(
        "Открыть Диспетчер устройств",
        "devmgmt.msc",
        "Проверьте устройства с восклицательным знаком; обновите или откатите "
        "недавно менявшиеся драйверы.",
        needs_admin=False,
    ))
    steps.append(FixStep(
        "Driver Verifier — поиск сбойного драйвера (для опытных)",
        "verifier",
        "Мощный, но рискованный инструмент: нагружает драйверы и вызывает BSOD "
        "на виновном. ВАЖНО: включайте проверку только сторонних драйверов и "
        "умейте отключить (verifier /reset в безопасном режиме). Может привести "
        "к циклу перезагрузок при неверной настройке.",
    ))
    return steps


def _hardware_steps() -> List[FixStep]:
    return [
        FixStep(
            "Убрать любой разгон CPU/GPU/памяти (вручную)",
            None,
            "STOP-коды 0x124/0x9C/0x101 почти всегда про железо. Верните все "
            "частоты и напряжения на заводские.",
            needs_admin=False,
        ),
        FixStep(
            "Проверить температуры и питание (вручную)",
            None,
            "Установите HWiNFO, проверьте температуры CPU/GPU под нагрузкой и "
            "стабильность напряжений блока питания.",
            needs_admin=False,
        ),
    ]


def _disk_steps() -> List[FixStep]:
    return [
        FixStep(
            "Полная проверка и починка диска",
            "chkdsk C: /f /r",
            "Исправляет ошибки файловой системы и ищет сбойные сектора. "
            "ВНИМАНИЕ: выполнится при перезагрузке и может занять часы.",
            needs_reboot=True,
        ),
        FixStep(
            "Проверить здоровье накопителя (SMART)",
            None,
            "Установите CrystalDiskInfo и посмотрите статус SMART — при "
            "«Тревога/Плохо» диск пора менять.",
            needs_admin=False,
        ),
    ]


def _gpu_steps() -> List[FixStep]:
    return [
        FixStep(
            "Чистая переустановка драйвера видеокарты",
            None,
            "Удалите драйвер GPU утилитой DDU (Display Driver Uninstaller) в "
            "безопасном режиме, затем поставьте свежий с сайта NVIDIA/AMD/Intel. "
            "Это лечит большинство ошибок 0x116/0xEA/0x10E.",
            needs_admin=False,
        ),
    ]


def _cleanup_step(a: DumpAnalysis) -> FixStep:
    return FixStep(
        "Удалить старые дампы после разбора",
        None,
        "Когда причина найдена, старые .dmp можно удалить прямо в списке слева, "
        "чтобы освободить место.",
        needs_admin=False,
    )


def build_plan(a: DumpAnalysis) -> List[FixStep]:
    """Собрать план действий под конкретный дамп."""
    steps: List[FixStep] = list(_base_safe_steps())

    name = a.bugcheck.name if a.bugcheck else ""
    code = a.bugcheck_code

    added_categories = set()

    def add(category: str, new_steps: List[FixStep]):
        if category in added_categories:
            return
        added_categories.add(category)
        steps.extend(new_steps)

    # Категоризация по STOP-коду.
    memory_codes = {0x1A, 0x50, 0xA, 0x12B, 0x109, 0x139}
    hardware_codes = {0x124, 0x9C, 0x101, 0x7F}
    disk_codes = {0xF4, 0xEF, 0x7A}
    gpu_codes = {0x116, 0xEA, 0x10E, 0x113}
    driver_codes = {0xD1, 0xC2, 0xC4, 0xC5, 0x4A, 0xBE, 0x9F, 0x133, 0x144,
                    0xCA, 0x19, 0xD5, 0x1E, 0x3B, 0x7E}

    low = (code & 0xFFFFFFFF) if code is not None else None

    if low in memory_codes:
        add("memory", _memory_steps())
    if low in hardware_codes:
        add("hardware", _hardware_steps())
    if low in disk_codes:
        add("disk", _disk_steps())
    if low in gpu_codes:
        add("gpu", _gpu_steps())
    if low in driver_codes or a.probable_module:
        add("driver", _driver_steps(a.probable_module))

    # Если ничего не подошло — добавим общий драйверный блок как самый частый.
    if not added_categories and code is not None:
        add("driver", _driver_steps(a.probable_module))

    # Видеодрайвер-специфичный виновник.
    if a.probable_module and a.probable_module.lower().startswith(
            ("nvlddmkm", "atikmdag", "amdkmdag", "dxgkrnl", "dxgmms",
             "igdkmd")):
        add("gpu", _gpu_steps())

    steps.append(_cleanup_step(a))
    return steps


def auto_steps(plan: List[FixStep]) -> List[FixStep]:
    """Только безопасные шаги, которые можно выполнить автоматически."""
    return [s for s in plan if s.safe_auto and s.command]


def format_plan(plan: List[FixStep]) -> str:
    """Текстовое представление плана для вкладки «Что делать»."""
    out: List[str] = []
    out.append("ПЛАН УСТРАНЕНИЯ (по убыванию вероятности/безопасности):")
    out.append("")
    for i, s in enumerate(plan, start=1):
        tags = []
        if s.safe_auto:
            tags.append("авто-безопасно")
        if s.needs_admin:
            tags.append("нужны права админа")
        if s.needs_reboot:
            tags.append("нужна перезагрузка")
        tag_str = f"  [{', '.join(tags)}]" if tags else ""
        out.append(f"{i}. {s.title}{tag_str}")
        out.append(f"   {s.explanation}")
        if s.command:
            out.append(f"   Команда: {s.command}")
        out.append("")
    out.append("Кнопка «Запустить безопасные проверки» выполнит только "
               "шаги с меткой «авто-безопасно» (SFC, DISM, chkdsk /scan).")
    return "\n".join(out)

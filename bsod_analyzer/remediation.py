# -*- coding: utf-8 -*-
"""Targeted remediation plans derived from the local diagnosis.

The planner does not spray SFC/DISM/CHKDSK at every BSOD.  Each automatic
command is a fixed, reviewed string from an allow-list and has a verification
step.  Destructive or hard-to-roll-back operations remain explicit manual
instructions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set

from .diagnosis import Diagnosis, diagnose
from .dump_parser import DumpAnalysis


@dataclass
class FixStep:
    # Keep the first fields compatible with the original prototype.
    title: str
    command: Optional[str]
    explanation: str
    needs_admin: bool = True
    safe_auto: bool = False
    needs_reboot: bool = False
    step_id: str = ""
    risk: str = "medium"          # read-only / low / medium / high
    verify_command: Optional[str] = None
    rationale: str = ""
    rollback: Optional[str] = None


# Commands below are constants rather than strings assembled from dump data.
# This is both a safety boundary and a defence against command injection from a
# malicious/corrupt debugger field.
CMD_SYSTEMINFO = "systeminfo"
CMD_RECENT_ERRORS = (
    'powershell.exe -NoProfile -NonInteractive -Command "Get-WinEvent -FilterHashtable '
    "@{LogName='System'; Level=1,2; StartTime=(Get-Date).AddDays(-7)} "
    '| Select-Object -First 80 TimeCreated,Id,ProviderName,Message | Format-List"'
)
CMD_DRIVERQUERY = "driverquery /v /fo csv"
CMD_ENUM_DRIVER_STORE = "pnputil /enum-drivers"
CMD_GPU_INFO = (
    'powershell.exe -NoProfile -NonInteractive -Command "Get-CimInstance '
    'Win32_VideoController | Select-Object Name,Status,DriverVersion,PNPDeviceID '
    '| Format-List"'
)
CMD_STORAGE_INFO = (
    'powershell.exe -NoProfile -NonInteractive -Command "Get-PhysicalDisk '
    '| Select-Object FriendlyName,MediaType,HealthStatus,OperationalStatus,Size '
    '| Format-Table -AutoSize"'
)
CMD_STORAGE_EVENTS = (
    'powershell.exe -NoProfile -NonInteractive -Command "Get-WinEvent '
    "-FilterHashtable @{LogName='System'; ProviderName='disk','stornvme','storahci',"
    "'iaStorAC','Ntfs'; StartTime=(Get-Date).AddDays(-14)} "
    '| Select-Object -First 100 TimeCreated,Id,ProviderName,Message | Format-List"'
)
CMD_CHKDSK_SCAN = "chkdsk C: /scan"
CMD_MEMORY_INFO = (
    'powershell.exe -NoProfile -NonInteractive -Command "Get-CimInstance '
    'Win32_PhysicalMemory | Select-Object DeviceLocator,Manufacturer,PartNumber,'
    'Capacity,Speed,ConfiguredClockSpeed | Format-Table -AutoSize"'
)
CMD_WHEA_EVENTS = (
    'powershell.exe -NoProfile -NonInteractive -Command "Get-WinEvent '
    "-FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WHEA-Logger'; "
    'StartTime=(Get-Date).AddDays(-30)} | Select-Object -First 100 '
    'TimeCreated,Id,LevelDisplayName,Message | Format-List"'
)
CMD_DISM_SCAN = "DISM /Online /Cleanup-Image /ScanHealth"
CMD_DISM_RESTORE = "DISM /Online /Cleanup-Image /RestoreHealth"
CMD_DISM_CHECK = "DISM /Online /Cleanup-Image /CheckHealth"
CMD_SFC = "sfc /scannow"
CMD_SFC_VERIFY = "sfc /verifyonly"


# Exact commands that the Autofix executor may run.  A step must match both ID
# and command; merely setting safe_auto=True is not sufficient.
AUTO_COMMAND_ALLOWLIST: Dict[str, str] = {
    "collect-systeminfo": CMD_SYSTEMINFO,
    "collect-recent-errors": CMD_RECENT_ERRORS,
    "collect-driverquery": CMD_DRIVERQUERY,
    "collect-driver-store": CMD_ENUM_DRIVER_STORE,
    "collect-gpu-info": CMD_GPU_INFO,
    "collect-storage-info": CMD_STORAGE_INFO,
    "collect-storage-events": CMD_STORAGE_EVENTS,
    "scan-filesystem": CMD_CHKDSK_SCAN,
    "collect-memory-info": CMD_MEMORY_INFO,
    "collect-whea-events": CMD_WHEA_EVENTS,
    "dism-scan": CMD_DISM_SCAN,
    "dism-restore": CMD_DISM_RESTORE,
    "sfc-repair": CMD_SFC,
}

_FORBIDDEN_AUTO_MARKERS = (
    "verifier",
    "chkdsk c: /f",
    "chkdsk c: /r",
    " /delete-driver",
    "ddu",
    "bcdedit",
    "bootrec",
    "diskpart",
    "format ",
    "flash",
    "firmware",
    "bios",
    "remove-item",
    "del /",
    "reg delete",
    "shutdown",
    "restart-computer",
)


def _step(
    step_id: str,
    title: str,
    explanation: str,
    command: Optional[str] = None,
    *,
    rationale: str,
    risk: str = "read-only",
    admin: bool = False,
    auto: bool = False,
    reboot: bool = False,
    verify: Optional[str] = None,
    rollback: Optional[str] = None,
) -> FixStep:
    return FixStep(
        title=title,
        command=command,
        explanation=explanation,
        needs_admin=admin,
        safe_auto=auto,
        needs_reboot=reboot,
        step_id=step_id,
        risk=risk,
        verify_command=verify,
        rationale=rationale,
        rollback=rollback,
    )


def _initial_evidence_steps() -> List[FixStep]:
    return [
        _step(
            "collect-systeminfo",
            "Снять базовый снимок системы",
            "Фиксирует версию Windows, модель ПК, BIOS, объём памяти и установленные обновления.",
            CMD_SYSTEMINFO,
            rationale="Нужен воспроизводимый контекст до любых изменений.",
            auto=True,
        ),
        _step(
            "collect-recent-errors",
            "Собрать свежие критические события System",
            "Читает последние ошибки и критические события за семь дней, ничего не меняя.",
            CMD_RECENT_ERRORS,
            rationale="События рядом по времени могут подтвердить устройство или подсистему.",
            auto=True,
        ),
    ]


def _driver_steps(d: Diagnosis) -> List[FixStep]:
    module = d.suspected_module
    label = module or "предполагаемого драйвера"
    return [
        _step(
            "collect-driverquery",
            "Снять список загруженных драйверов",
            "Сохраняет версии, пути и состояние драйверов для сопоставления с дампом.",
            CMD_DRIVERQUERY,
            rationale="Категория анализа — драйвер; сначала фиксируем фактические версии.",
            auto=True,
        ),
        _step(
            "collect-driver-store",
            "Снять список пакетов Driver Store",
            "Показывает опубликованные INF, поставщиков, классы и даты пакетов.",
            CMD_ENUM_DRIVER_STORE,
            rationale="Позволяет связать .sys с установленным пакетом без удаления драйвера.",
            auto=True,
        ),
        _step(
            "review-driver-change",
            "Сопоставить {} с устройством и недавними изменениями".format(label),
            "Проверьте свойства файла, службу драйвера, INF-пакет и PnP-устройство. "
            "Сравните дату установки с первым сбоем.",
            rationale="Обновлять драйвер безопасно только после идентификации устройства и пакета.",
            risk="read-only",
        ),
        _step(
            "manual-driver-update-or-rollback",
            "Осознанно обновить или откатить подтверждённый драйвер",
            "Берите пакет с сайта производителя устройства/ПК. Если сбои начались сразу "
            "после обновления, предпочтительнее откат к сохранённой версии.",
            rationale="Действие адресное, но меняет kernel-компонент и требует точки возврата.",
            risk="medium",
            admin=True,
            reboot=True,
            verify="После перезагрузки проверить новые дампы и повторить целевой сценарий.",
            rollback="Сохранить текущий INF/установщик и заранее записать способ возврата версии.",
        ),
        _step(
            "driver-verifier-manual-only",
            "Driver Verifier — только отдельный экспертный сценарий",
            "Не запускается Autofix. Может намеренно вызвать BSOD и цикл загрузки. Использовать "
            "только для выбранных сторонних драйверов при наличии инструкции verifier /reset "
            "из безопасного режима.",
            command="verifier",
            rationale="Инструмент полезен, когда обычный дамп не локализует драйвер.",
            risk="high",
            admin=True,
            reboot=True,
            rollback="verifier /reset из безопасного режима или среды восстановления.",
        ),
    ]


def _gpu_steps(d: Diagnosis) -> List[FixStep]:
    return [
        _step(
            "collect-gpu-info",
            "Снять состояние графических адаптеров",
            "Фиксирует модель, статус, версию драйвера и PnP ID каждого GPU.",
            CMD_GPU_INFO,
            rationale="Дамп относится к графическому тракту; нужна точная модель и версия.",
            auto=True,
        ),
        _step(
            "check-gpu-stability",
            "Вернуть GPU к штатным частотам и проверить температуры",
            "Уберите разгон/undervolt, проверьте питание, температуры и повторяемость сбоя "
            "до переустановки ПО.",
            rationale="TDR может быть как драйверным, так и аппаратным; этот тест разделяет причины.",
            risk="low",
            verify="Повторить нагрузку, при которой возникал сбой, с журналированием температур.",
            rollback="Записать текущий профиль перед сбросом настроек.",
        ),
        _step(
            "manual-clean-gpu-driver",
            "Чисто переустановить драйвер GPU только при подтверждении",
            "Сначала скачать подходящий пакет и подготовить возврат. DDU допустим только как "
            "ручная процедура в безопасном режиме; Autofix его не запускает.",
            rationale="Согласованные графические сигналы делают переустановку обоснованной.",
            risk="high",
            admin=True,
            reboot=True,
            verify="После перезагрузки проверить версию драйвера и повторить проблемный сценарий.",
            rollback="Иметь предыдущий стабильный установщик и точку восстановления.",
        ),
    ] + _driver_steps(d)[:3]


def _storage_steps() -> List[FixStep]:
    return [
        _step(
            "collect-storage-info",
            "Снять состояние физических накопителей",
            "Читает HealthStatus и OperationalStatus накопителей без изменения дисков.",
            CMD_STORAGE_INFO,
            rationale="Категория сбоя связана с хранением данных.",
            auto=True,
        ),
        _step(
            "collect-storage-events",
            "Собрать события диска, NVMe/SATA и NTFS",
            "Ищет ошибки контроллера, сбросы устройства и ошибки файловой системы.",
            CMD_STORAGE_EVENTS,
            rationale="События помогают отделить файловую систему от контроллера/железа.",
            auto=True,
        ),
        _step(
            "scan-filesystem",
            "Онлайн-проверка файловой системы C:",
            "Запускает только chkdsk /scan: без блокировки тома, /f и /r.",
            CMD_CHKDSK_SCAN,
            rationale="Проверка уместна именно для storage-категории.",
            risk="low",
            admin=True,
            auto=True,
            verify="chkdsk C: /scan",
        ),
        _step(
            "manual-storage-firmware",
            "Проверить прошивку и драйвер контроллера вручную",
            "Сопоставьте модель накопителя, версию прошивки, драйвер AHCI/NVMe/RST и "
            "рекомендации производителя. Не прошивайте устройство наугад.",
            rationale="Ошибки storage-стека нередко исправляются производителем, но прошивка рискованна.",
            risk="high",
            admin=True,
            reboot=True,
            rollback="Перед прошивкой сделать резервную копию и проверить возможность отката.",
        ),
    ]


def _memory_steps() -> List[FixStep]:
    return [
        _step(
            "collect-memory-info",
            "Снять конфигурацию модулей памяти",
            "Фиксирует производитель, part number, объём, номинальную и настроенную частоту.",
            CMD_MEMORY_INFO,
            rationale="Повреждение памяти не равно доказанной поломке RAM; нужен контекст конфигурации.",
            auto=True,
        ),
        _step(
            "disable-memory-overclock",
            "Временно отключить XMP/EXPO и разгон памяти",
            "Верните JEDEC/Auto, затем проверьте повторяемость. Изменяйте одну переменную за раз.",
            rationale="Нестабильный профиль часто имитирует дефект RAM или драйвера.",
            risk="medium",
            reboot=True,
            verify="Повторить проблемную нагрузку на штатных настройках.",
            rollback="Сфотографировать исходные параметры UEFI перед изменением.",
        ),
        _step(
            "manual-memory-test",
            "Провести последовательный тест ОЗУ",
            "Сначала Windows Memory Diagnostic как быстрый сигнал, затем несколько проходов "
            "MemTest86. При ошибках тестировать планки и слоты по одной комбинации.",
            rationale="Только воспроизводимые ошибки позволяют локализовать модуль, слот или контроллер.",
            risk="low",
            reboot=True,
            verify="Зафиксировать номер теста, адреса ошибок, планку и слот.",
        ),
    ]


def _hardware_steps() -> List[FixStep]:
    return [
        _step(
            "collect-whea-events",
            "Собрать события WHEA-Logger",
            "Читает аппаратные записи WHEA за 30 дней.",
            CMD_WHEA_EVENTS,
            rationale="WHEA_ERROR_RECORD и события часто называют компонент точнее общего STOP 0x124.",
            auto=True,
        ),
        _step(
            "return-stock-settings",
            "Вернуть CPU/GPU/RAM к заводским настройкам",
            "Уберите overclock, undervolt, PBO/MCE и нестандартный XMP/EXPO. Затем повторите тест.",
            rationale="Это наиболее информативный обратимый тест аппаратной стабильности.",
            risk="medium",
            reboot=True,
            verify="Повторить ту же нагрузку и сравнить WHEA/дампы.",
            rollback="Сохранить профиль UEFI или сфотографировать исходные значения.",
        ),
        _step(
            "inspect-thermals-power",
            "Проверить температуры, питание и физические соединения",
            "Логируйте температуры и частоты под нагрузкой; проверьте питание CPU/GPU, "
            "посадку RAM и кабели. Не меняйте несколько компонентов одновременно.",
            rationale="Перегрев и просадки питания дают те же общие аппаратные STOP-коды.",
            risk="medium",
            verify="Сопоставить момент ошибки с датчиками и WHEA-событиями.",
        ),
    ]


def _system_corruption_steps() -> List[FixStep]:
    # Ordering is intentional: repair the component store before SFC consumes it.
    return [
        _step(
            "dism-scan",
            "Проверить хранилище компонентов DISM",
            "ScanHealth выполняет диагностику без восстановления.",
            CMD_DISM_SCAN,
            rationale="Диагноз указывает на возможное повреждение компонентов Windows.",
            risk="read-only",
            admin=True,
            auto=True,
            verify=CMD_DISM_CHECK,
        ),
        _step(
            "dism-restore",
            "Восстановить хранилище компонентов DISM",
            "RestoreHealth изменяет только повреждённые компоненты Windows и может использовать Windows Update.",
            CMD_DISM_RESTORE,
            rationale="Выполняется после ScanHealth и только в категории system_corruption.",
            risk="low",
            admin=True,
            auto=True,
            verify=CMD_DISM_CHECK,
        ),
        _step(
            "sfc-repair",
            "Проверить и восстановить системные файлы SFC",
            "SFC запускается после DISM, чтобы использовать исправное хранилище компонентов.",
            CMD_SFC,
            rationale="Последовательность DISM → SFC снижает вероятность повторной ошибки восстановления.",
            risk="low",
            admin=True,
            auto=True,
            verify=CMD_SFC_VERIFY,
        ),
    ]


def _unknown_steps() -> List[FixStep]:
    return [
        _step(
            "improve-dump-quality",
            "Настроить kernel/automatic memory dump и повторить сбор",
            "Проверьте файл подкачки на системном диске и настройку Startup and Recovery. "
            "Следующий более полный дамп может содержать отсутствующий стек/объекты.",
            rationale="Текущих доказательств недостаточно для безопасного ремонта.",
            risk="medium",
            admin=True,
            reboot=True,
            verify="После следующего сбоя проверить тип и размер нового дампа.",
            rollback="Записать исходную настройку дампа и файла подкачки.",
        ),
        _step(
            "correlate-changes",
            "Сопоставить первый сбой с обновлениями и изменениями",
            "Проверьте историю Windows Update, драйверов, BIOS, нового железа и ПО уровня ядра.",
            rationale="Временная корреляция часто сужает поиск без рискованных действий.",
            risk="read-only",
        ),
    ]


def build_plan(a: DumpAnalysis) -> List[FixStep]:
    d = a.diagnosis if isinstance(a.diagnosis, Diagnosis) else diagnose(a)
    steps = _initial_evidence_steps()
    if d.category == "driver":
        steps.extend(_driver_steps(d))
    elif d.category == "gpu":
        steps.extend(_gpu_steps(d))
    elif d.category == "storage":
        steps.extend(_storage_steps())
    elif d.category == "memory":
        steps.extend(_memory_steps())
    elif d.category == "hardware":
        steps.extend(_hardware_steps())
    elif d.category == "system_corruption":
        steps.extend(_system_corruption_steps())
    elif d.category == "application":
        steps.extend([
            _step(
                "application-context",
                "Собрать версию приложения и его собственные журналы",
                "Проверьте модуль исключения, версию приложения, плагины и события Application.",
                rationale="User-mode дамп не оправдывает системный ремонт Windows.",
                risk="read-only",
            )
        ])
    else:
        steps.extend(_unknown_steps())
    return _dedupe_steps(steps)


def is_auto_safe_step(step: FixStep) -> bool:
    if not step.safe_auto or not step.command or not step.step_id:
        return False
    if step.risk not in ("read-only", "low"):
        return False
    expected = AUTO_COMMAND_ALLOWLIST.get(step.step_id)
    if expected is None or expected != step.command:
        return False
    lowered = step.command.lower()
    return not any(marker in lowered for marker in _FORBIDDEN_AUTO_MARKERS)


def auto_steps(plan: Iterable[FixStep]) -> List[FixStep]:
    return [step for step in plan if is_auto_safe_step(step)]


def format_plan(plan: List[FixStep]) -> str:
    out: List[str] = [
        "ПЛАН УСТРАНЕНИЯ — ОТ ДОКАЗАТЕЛЬСТВ К ИЗМЕНЕНИЯМ",
        "",
        "Autofix выполняет только фиксированные read-only/low-risk команды. "
        "Ручная пометка safe_auto в коде не обходит allow-list.",
        "",
    ]
    risk_ru = {
        "read-only": "только чтение",
        "low": "низкий",
        "medium": "средний",
        "high": "высокий",
    }
    for index, step in enumerate(plan, start=1):
        tags = ["риск: {}".format(risk_ru.get(step.risk, step.risk))]
        if is_auto_safe_step(step):
            tags.append("доступно в Autofix")
        if step.needs_admin:
            tags.append("нужен администратор")
        if step.needs_reboot:
            tags.append("нужна перезагрузка")
        out.append("{}. {} [{}]".format(index, step.title, ", ".join(tags)))
        out.append("   Зачем в этом случае: {}".format(step.rationale))
        out.append("   Что делать: {}".format(step.explanation))
        if step.command:
            out.append("   Команда: {}".format(step.command))
        if step.verify_command:
            out.append("   Проверка результата: {}".format(step.verify_command))
        if step.rollback:
            out.append("   Возврат/страховка: {}".format(step.rollback))
        out.append("")
    return "\n".join(out)


def _dedupe_steps(steps: Iterable[FixStep]) -> List[FixStep]:
    result: List[FixStep] = []
    seen: Set[str] = set()
    for step in steps:
        key = step.step_id or step.title
        if key not in seen:
            seen.add(key)
            result.append(step)
    return result

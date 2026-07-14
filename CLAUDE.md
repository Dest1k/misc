# CLAUDE.md — передача проекта следующему Claude/Opus

Привет. Этот документ оставлен специально для твоего следующего прохода по
`BSOD Dump Analyzer`. Пользователь хочет, чтобы ты не переписывал всё с нуля, а
**внимательно проверил, попытался сломать и полезно усилил** текущую реализацию.

## Что здесь строится

Windows/Tkinter-программа должна:

1. максимально точно разобрать crash dump локально;
2. отделить достоверные факты от диагностических гипотез;
3. честно показать качество и ограничения вывода;
4. дать адресный порядок действий;
5. по возможности безопасно автоматизировать проверяемые исправления.

ИИ — только опциональное второе мнение. Основной продукт обязан быть полностью
полезен без Claude/Codex/Grok.

## Непереговорные продуктовые решения

### 1. ИИ выключен по умолчанию

- `config.DEFAULT_CONFIG["ai_enabled"] == False`.
- Старый config без ключа `ai_enabled` тоже означает `False`.
- Пока пользователь явно не поставил галочку, AI runner и обнаружение CLI не
  создаются, кнопки/combobox/вкладка ИИ отсутствуют в layout.
- Снятие галочки скрывает их снова без перезапуска.
- Не превращай локальный отчёт в «подготовку к запросу в LLM».

### 2. Evidence first, никакой магической уверенности

`diagnosis.py` сопоставляет независимые источники:

- `Probably caused by`;
- `IMAGE_NAME`;
- `MODULE_NAME`;
- `SYMBOL_NAME`;
- повторяемость модуля в `STACK_TEXT`;
- `FAILURE_BUCKET_ID` / `FAILURE_ID_HASH`;
- метаданные `lmvm`;
- STOP-код и параметры;
- качество символов, полноту CDB-сеанса и расхождения `.bugcheck`.

Один источник — подсказка, не доказательство. Значение `confidence` —
качественная градация согласованности данных, **не вероятность**. Не выводи
проценты без реальной калиброванной модели и набора размеченных дампов.

### 3. Не обвинять системные прокси

`ntoskrnl.exe`, `ntkrnlmp.exe`, `hal.dll`, `Wdf01000.sys`, `ndis.sys`,
`tcpip.sys`, `storport.sys`, `stornvme.sys`, `ntfs.sys`, `dxgkrnl.sys`,
`dxgmms2.sys`, `memory_corruption` часто являются местом проявления или
посредником. Они могут помочь выбрать категорию, но не должны становиться
конкретным root cause из одной строки WinDbg.

Особая регрессия: не используй расплывчатый substring matching. Строка `nvme`
не имеет отношения к NVIDIA только потому, что начинается на `nv`.

### 4. Autofix — safety boundary

`remediation.AUTO_COMMAND_ALLOWLIST` содержит точные строки разрешённых команд.
Autofix должен проверить одновременно:

- `safe_auto=True`;
- риск только `read-only` или `low`;
- известный `step_id`;
- точное совпадение команды с allow-list;
- отсутствие опасных маркеров.

Никогда не автоматизируй без отдельной транзакционной архитектуры:

- Driver Verifier;
- DDU;
- удаление/замену драйверов;
- BIOS/UEFI/firmware;
- `chkdsk /f /r`;
- BCD/bootloader;
- форматирование/partitioning;
- произвольный rollback;
- команды, собранные из полей дампа.

Каждый автоматический шаг обязан сохранить stdout, stderr, exit code,
длительность, verification result и общий JSON. «Команда стартовала» не равно
«исправление успешно».

## Что изменено относительно первого прототипа

### `dump_parser.py`

- Исправлены реальные x86 offsets `DUMP_HEADER32`:
  `MachineImageType=0x20`, `BugCheckCode=0x28`, параметры с `0x2C`.
  Старый тест повторял неправильные x64 offsets и поэтому ложно проходил.
- MINIDUMP directory/RVA/size проверяются относительно размера файла; есть cap
  на число потоков и размер stream.
- CDB выполняет `!analyze -v`, `.bugcheck`, `kv 40`, blackbox-команды и
  bugcheck-specific `!errrec`/`!irp`/`ln`.
- Заголовок сверяется с `.bugcheck`.
- Извлекаются image/module/symbol/caused-by/process/bucket/hash/stack/symbol
  quality/exit code/timeout/duration.
- Для строгого токена стороннего модуля выполняется дополнительный `lmvm` без
  shell interpolation.

### `diagnosis.py`

Новый детерминированный движок. Он выдаёт `Diagnosis` с category/title/summary,
качеством, evidence, reducers, alternatives, limitations и только при
согласованных источниках — `suspected_module`.

### `report.py`

Отчёт разделён на факты, вывод, основания, слабые места, альтернативы,
справочный фон и ограничения. Типичные причины из `bugcheck_db` больше не
выдаются за диагноз конкретного ПК.

### `remediation.py`

План строится по категории. Универсальная тройка SFC/DISM/CHKDSK удалена:

- storage → disk/controller facts, storage events, только тогда `chkdsk /scan`;
- memory → DIMM config, XMP/EXPO, последовательный memory test;
- hardware/WHEA → WHEA events, stock settings, temperatures/power;
- driver → driverquery, Driver Store, mapping to device, deliberate update;
- GPU → exact adapter/version/stability, then manual clean install if justified;
- system corruption → DISM Scan/Restore, затем SFC;
- unknown → улучшение дампа и сбор корреляций вместо ремонта наугад.

### `autofix.py`

Вместо временного BAT создаёт retained PowerShell run directory в
`%LOCALAPPDATA%\BSODAnalyzer\reports`, manifest, per-step stdout/stderr,
verification logs, `summary.json` и `summary.txt`.

### `gui.py` / `config.py`

ИИ стал настоящим runtime opt-in. Настройки анализа отделены от вкладки
«Опциональный ИИ».

## Что проверить в первую очередь

Пожалуйста, начни не с новых фич, а с adversarial review:

1. **Синтаксис и Python 3.8.** Прогони compileall и unittest именно на 3.8.
2. **PowerShell quoting.** Проверь `run_autofix.ps1` на реальной Windows 10/11,
   включая команды с вложенными кавычками, кириллицу и пробелы в пути.
3. **Verification allow-list.** Убедись, что не только основная команда, но и
   verification command не может быть подменена объектом `FixStep` извне.
4. **CDB fixtures.** Добавь обезличенные output fixtures разных версий WinDbg:
   x64/x86/ARM64, poor symbols, localized/noisy output, WHEA, 0x9F, minidump,
   kernel dump, Driver Verifier dump.
5. **Regex robustness.** Ищи multiline/whitespace/backtick/duplicate field
   cases; парсер не должен падать или смешивать первый и второй CDB session.
6. **Confidence calibration.** Попытайся создать ложное high-confidence
   назначение стороннего модуля с искусственным bucket/stack. Любая строка,
   происходящая из одного вывода `!analyze`, формально коррелирована; подумай,
   как лучше моделировать независимость.
7. **System proxies.** Добавь больше Windows infrastructure modules и случаи,
   где proxy всё же полезен только как category signal.
8. **MDMP security.** Fuzz directory count/RVA/size/overflow/duplicate streams.
9. **GUI lifecycle.** Быстро включать/выключать ИИ во время активного запроса,
   закрывать Settings через X, отменять изменения, включать при отсутствии CLI.
10. **Autofix results.** Exit code 0 не всегда означает здоровый результат
    (`SFC`, `DISM`, `chkdsk` имеют собственную семантику). Добавь parsers статуса
    поверх raw exit/verify, не скрывая исходные логи.

## Наиболее полезные следующие фичи

### A. Корреляция серии дампов

Это главный прирост точности. Создай incident model и группируй дампы по:

- `FAILURE_ID_HASH`/bucket;
- bugcheck + параметры;
- повторяющимся сторонним модулям и стек-фреймам;
- временному окну;
- одному PnP device/driver package.

Один случайный модуль в одном дампе слаб; повторяемость в пяти независимых
падениях значительно сильнее. При этом не превращай count в вероятность без
калибровки.

### B. `.sys → service → INF → Driver Store → PnP device`

Нужен read-only resolver, который связывает файл с:

- Service registry entry;
- loaded module path;
- published INF и provider/version/date;
- signed driver catalog;
- PnP instance и hardware IDs;
- текущим/предыдущим package.

Только после этого можно проектировать настоящий driver Autofix как
транзакцию: snapshot → package backup → change → reboot → health check →
rollback on regression. Пока этого нет, замена драйвера остаётся ручной.

### C. Portable support bundle

Экспортируй обезличенный zip/JSON с локальным отчётом, CDB evidence, event
snippets, driver/device metadata и Autofix results. Не включай сам dump без
явного согласия: он может содержать чувствительные данные.

### D. Confidence provenance

Сделай machine-readable explanation graph: hypothesis → evidence edges →
parser/source → reliability. Это облегчит тестирование и сравнение нескольких
дампов.

## Команды проверки

```bat
python -m compileall -q bsod_analyzer tests
python -m unittest discover -s tests -v
```

На Windows дополнительно:

```bat
python run_analyzer.pyw
```

Ручной smoke test:

1. Запустить с чистым config — элементов ИИ нет.
2. Поставить галочку — они появились.
3. Снять — исчезли без restart.
4. Проанализировать synthetic x86 dump и настоящий minidump.
5. Открыть план разных категорий и убедиться, что SFC/DISM/chkdsk не расползлись
   во все случаи.
6. Запустить Autofix read-only steps и проверить все файлы отчёта.

## Просьба к тебе

Не будь вежливым ревьюером. Ищи контрпримеры, race conditions, unsafe quoting,
ложные назначения и способы просунуть опасную команду. Исправляй найденное,
добавляй тест, затем оставь в этом файле краткий раздел со своими решениями и
неустранёнными рисками, чтобы следующий агент продолжил эстафету.

---

## Проход Claude (Opus 4.8): что сделано и остаточные риски

Провёл adversarial review как просили. Ключевая находка: ветка была помечена
«implementation complete / review-ready», но **15 тестов падали**, а
`dump_parser.py` вообще не был изменён — доки и тесты описывали усиленный
парсер, которого в коде не было. Привёл реализацию в соответствие с
задокументированным контрактом.

### Что исправлено/добавлено

1. **Реализован недостающий слой `dump_parser.py`** (то, что этот файл выше уже
   обещал, но чего в коде не было):
   - правильные x86-смещения `DUMP_HEADER32` (`0x20/0x28/0x2C`);
   - защита разбора MDMP: лимит числа потоков и проверка RVA/размера каждого
     потока против размера файла (сообщения содержат «границы»/«много потоков»);
   - `build_cdb_commands()` — команды строятся только из числовых параметров
     (`.bugcheck`, `kv 40`, `!errrec` для 0x124, `!irp` для 0x9F@arg1==3);
   - `enrich_from_cdb()` — извлечение IMAGE/MODULE/SYMBOL/caused_by/bucket/hash/
     process/stack и **кросс-проверка STOP-кода** (`bugcheck_mismatch`);
   - `parse_lmvm()` + `safe_module_for_lmvm()` со строгой валидацией токена
     (отказ при пробелах/`;`/`!`/`&` — команда с полем дампа не собирается);
   - все поля `DumpAnalysis`, которые напрямую читают `report.py`/`gui.py`.
2. **`analyze()` один раз считает и сохраняет `result.diagnosis`** (ленивый
   импорт разрывает цикл). Раньше `diagnosis` оставался `None`, и GUI/тех-вкладка
   показывали категорию «unknown», а `diagnose()` вызывался повторно.
3. **Два бага в самом тест-сьюте, из-за которых ветка была «зелёной на бумаге»:**
   - `make_kernel32_dump` «отравлял» смещение `0x38`, где реально лежит
     `BugCheckParameter4` → перенёс отраву на `0x3C` (место старого ошибочного
     чтения), не затрагивая настоящий параметр;
   - `test_dangerous_operations_...`: маркеры `" /f"`/`" /r"` ложно совпадали с
     безопасными `/fo` (driverquery) и `/restorehealth` (DISM) — это ровно тот
     «расплывчатый substring matching», о котором предупреждает раздел 3.
     Заменил на точные опасные формы + `regex chkdsk /[fr]`;
   - удалён устаревший `tests/test_parser.py` (полностью заменён `test_analyzer.py`).
4. **Фича A — корреляция серии дампов** (`correlation.py` + тесты + кнопка
   «🔗 Корреляция серии» и вкладка). Повторение модуля в нескольких независимых
   падениях усиливает подозрение; счётчик **не** превращается в вероятность,
   системные посредники исключены из повторяющихся виновников.

Результат: **41 тест зелёный** на Python 3.11 и 3.12; `compileall` чистый; GUI
собирается и проходит headless smoke (анализ, диагностика, корреляция,
жизненный цикл opt-in ИИ).

### Остаточные риски / не сделано (эстафета следующему)

- **Фича B** (resolver `.sys → service → INF → Driver Store → PnP`) —
  только дизайн-док, не реализована. Настоящий транзакционный driver Autofix
  по-прежнему отсутствует; замена драйверов остаётся manual-only.
- **CDB-фикстуры** (пункт 4 списка проверок) всё ещё не добавлены: `stack_modules`
  и `symbol_status` в `enrich_from_cdb` — эвристики по одному `!analyze`, на
  localized/зашумлённых выводах WinDbg возможны неточности.
- **`correlate()` при `use_cdb=True`** последовательно гоняет cdb по каждому
  дампу — на большом `MEMORY.DMP` это долго; таймаут общий, прогресс не пошаговый.
- **Калибровка confidence** (пункт 6) не решена: независимость сигналов из одного
  `!analyze` моделируется грубо.
- **PowerShell Autofix** (пункт 2) не проверялся на реальной Windows с кириллицей
  и вложенными кавычками — проверены только состав шагов и логирование.

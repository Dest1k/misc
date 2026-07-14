# Review handoff

Основная записка для Claude находится в [`CLAUDE.md`](CLAUDE.md).

Перед дополнениями сначала проверить:

```bat
python -m compileall -q bsod_analyzer tests
python -m unittest discover -s tests -v
```

Критические инварианты:

- ИИ выключен по умолчанию и не инициализируется до opt-in.
- Факт, гипотеза и ограничение не смешиваются.
- Один `Probably caused by` не назначает виновника.
- Windows proxy modules не выдаются за root cause.
- Autofix принимает только точное совпадение ID + command + verification с allow-list.
- Driver Verifier, DDU, driver removal, firmware, `chkdsk /f /r` и boot operations остаются manual-only.
- Каждый автоматический шаг сохраняет stdout/stderr/exit/verification/JSON.

Главный следующий прирост точности: корреляция серии дампов и read-only resolver
`.sys → service → INF → Driver Store → PnP device`.

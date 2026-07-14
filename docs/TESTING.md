# Testing

Cross-platform unit validation:

```bat
python -m compileall -q bsod_analyzer tests
python -m unittest discover -s tests -v
```

Windows smoke test:

1. Start with no config and confirm AI controls are absent.
2. Enable AI in settings, confirm controls appear; disable and confirm removal.
3. Analyze a real minidump with symbols and inspect facts versus hypothesis.
4. Run read-only Autofix steps and inspect manifest, stdout/stderr and summary.
5. Confirm Driver Verifier/DDU/driver removal/firmware/chkdsk `/f` or `/r` never
   appear in automatic steps.

Security tests must cover malformed MDMP ranges, proxy-module false positives,
command and verification allow-list bypass attempts, and dump-controlled module
injection.

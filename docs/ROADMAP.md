# Accuracy roadmap

1. ~~Correlate multiple dumps into one incident with repeatability evidence.~~
   **Done** — see `correlation.py` and the "🔗 Корреляция серии" action.
2. Resolve `.sys` to service, INF package, signature and PnP device read-only.
3. Add real, anonymized WinDbg output fixtures and parser fuzzing.
4. Calibrate confidence grades against reviewed incidents without presenting
   them as probabilities.
5. Parse semantic outcomes of SFC/DISM/CHKDSK in addition to raw exit codes.
6. Design transactional driver repair with snapshot, backup, reboot health
   check and rollback before automating any package change.

# Incident correlation design sketch

A future `Incident` should group dumps by time window and retain per-dump raw
evidence. Candidate grouping features: failure hash/bucket, bugcheck+parameters,
repeated non-proxy stack modules, driver package/device identity and boot/session.

Never collapse conflicting dumps into one conclusion silently. Show support
counts, contradictions and missing data. Counts improve evidence quality but do
not become calibrated probabilities by themselves.

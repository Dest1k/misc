# Architecture

```text
dump_finder
    ↓
dump_parser.parse_header
    ↓
dump_parser.execute_cdb / enrich_from_cdb / parse_lmvm
    ↓
diagnosis.diagnose
    ├── report.build_human_report
    └── remediation.build_plan
             ↓
       remediation.auto_steps (strict policy)
             ↓
       autofix.build_safe_script / run_safe_steps
```

`DumpAnalysis` is the structured evidence container. `Diagnosis` is an
interpretation and must not mutate raw facts. `FixStep` carries rationale, risk,
verification and rollback metadata. The GUI renders these layers and owns no
diagnostic heuristics.

AI backends receive a local report as optional review material only after
explicit opt-in; no core module depends on an AI result.

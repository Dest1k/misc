# Autofix report schema v1

`summary.json` contains run metadata and an array of steps. Each step records:

- `id`, `title`, exact `command`;
- `exit_code`, `duration_ms`, `launch_error`;
- stdout/stderr file paths;
- exact `verification_command`, verification exit/status and logs;
- final `status`.

Raw logs are authoritative. Future semantic parsers may add fields but should
not rewrite or delete version-1 evidence.

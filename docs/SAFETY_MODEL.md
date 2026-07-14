# Autofix safety model

## Trust boundaries

Untrusted inputs include dump bytes, file names, WinDbg output, module/symbol
names, failure buckets and any future imported support bundle. None of them may
be interpolated into a shell command.

Automatic execution accepts only locally constructed `FixStep` objects that
match a reviewed tuple:

```text
step_id + exact command + exact verification command + risk class
```

A boolean `safe_auto=True` is not authorization by itself.

## Forbidden automatic operations

- Driver Verifier and deliberate crash induction
- DDU or driver package removal/replacement
- firmware/BIOS/UEFI updates
- `chkdsk /f`, `chkdsk /r`
- BCD/boot repair or partition changes
- formatting/deletion/registry deletion
- reboot/shutdown
- any command assembled from dump-controlled data

## Result semantics

Launch success is not repair success. Every step records raw output, stderr,
exit code, duration and a separate verification result. Tool-specific semantic
parsers may add interpretation later, but must never discard the raw evidence.

## Privacy

Crash dumps may contain secrets and user data. They are ignored by git and must
not be included in support bundles or AI prompts without explicit consent.

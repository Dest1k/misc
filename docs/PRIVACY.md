# Crash dump privacy

Crash dumps can contain fragments of documents, credentials, tokens, browser
state, process memory and personally identifiable data.

- `*.dmp` and `*.xwd` remain ignored by git.
- The application analyzes files locally by default.
- Enabling an AI backend does not upload the dump itself; only the generated
  text prompt is passed to the selected CLI.
- A future support-bundle exporter must default to structured, redacted facts
  and require separate explicit consent before including a raw dump.
- Logs should avoid copying arbitrary memory or unlimited debugger output into
  external tickets.

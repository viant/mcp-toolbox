# browserCaptureStart (alias: webdriverCaptureStart)

Starts Chrome/Edge console+network capture.

## Input
- `sessionID`: `host:port`
- `sinkURL`: optional `file://...` JSONL sink (via `viant/afs`)
- `flushIntervalMs`: sink sync interval (default 500)
- `maxBodyBytes`: cap per body (default 1,000,000)
- `redact`: default true

# browserCaptureStart (alias: webdriverCaptureStart)

Starts Chrome/Edge console+network capture.

## Input
- `sessionID`: `host:port`
- `sinkURL`: optional `file://...` sink (via `viant/afs`)
  - when `splitArtifacts=false` (default): writes JSONL to `sinkURL`
  - when `splitArtifacts=true`: treats `sinkURL` as a directory base and writes:
    - `index.jsonl`
    - `roundtrip/request_00001.json` (5-digit padded)
    - `roundtrip/response_00001.json` (5-digit padded)
    - `ws/ws_00001.json` (5-digit padded; WebSocket frames, best-effort)
    - `streams/stream_00001.json` (5-digit padded; SSE/EventSource messages, best-effort)
- `flushIntervalMs`: sink sync interval (default 500)
- `maxBodyBytes`: cap per body (default 1,000,000)
- `redact`: default true
- `splitArtifacts`: default false

Notes:
- WebSocket frames and EventSource (SSE) messages are captured best-effort via Chrome performance logs (CDP `Network.*` events).
- Cached and streaming responses may not always have response bodies available via `Network.getResponseBody`; check `responseBodyError` / `dataReceivedBytes` and cache flags (`servedFromCache`, `fromDiskCache`, `fromServiceWorker`) in artifacts.

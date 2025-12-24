# Browser MCP Server

This package provides a Browser MCP server with an Endly-compatible WebDriver runner, plus optional Chrome/Edge capture (console + network) with request/response headers and bodies.

## Build / Run

```bash
go run ./browser/cmd/browser-mcp -a :8089
```

To monitor what the agent is doing (disable headless):

```bash
go run ./browser/cmd/browser-mcp -a :8089 --headful
```

## WebDriver tools

- `browserStart` / `browserStop`: starts/stops local `chromedriver` or `geckodriver` (auto-downloads if missing).
- `browserOpen` / `browserClose`: opens/closes a browser session (auto-starts a local driver for `localhost:PORT` sessions).
- `browserRun`: runs Endly-style commands.
- `browserCallDriver` / `browserCallElement`: reflection proxies to selenium WebDriver/WebElement methods.
- `browserDriverInstall` / `browserDriverUpdate`: install or update driver binaries (chromedriver supports `"stable"` / major / full version).
- `browserGetSource`: returns page source HTML (optionally writes to `destURL` via `viant/afs`).
- `browserGetDOM`: returns DOM `outerHTML` (cross-browser) or Chrome/Edge CDP snapshot.
- `browserSessions`: lists open sessions (or all known sessions with `includeAll=true`).
- `browserEvalJS`: executes JavaScript (optionally writes result JSON to `destURL` via `viant/afs`).

Legacy aliases (kept for compatibility): `webdriver*`.

## Capture tools (Chrome/Edge only)

Capture uses ChromeDriver performance logs (CDP events) and can fetch response bodies through ChromeDriver CDP endpoints.

- `browserCaptureStart`: starts capture; optionally streams JSONL to `sinkURL` (`file://...`) via `viant/afs`.
- `browserCaptureStop`: drains and closes the sink.
- `browserCaptureExport`: returns an in-memory snapshot (useful for small captures).

## Screenshot tool

- `browserScreenshot`: captures a PNG and writes it to `destURL` (defaults to a `file://` path under system temp); returns only the path.
- `browserScreenshotData`: returns a base64 screenshot inline (avoid for large images).

## Navigation guard

`browserRun` intercepts `get(url)` and applies a guard:
- sets page load timeout (`navigation.timeoutMs`)
- on timeout: warn/continue and (optionally) autoscroll for a short duration
- early stop based on DOM stability + CDP-derived network idle (when available)

## Example (capture to file)

1) Start + open
2) Start capture with sink
3) Run commands
4) Stop capture

Sink output is JSONL with events:
- `{"type":"console","entry":{...}}`
- `{"type":"network","tx":{...}}`

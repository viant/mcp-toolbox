# browserEvalJS (alias: webdriverEvalJS)

Executes JavaScript in the context of the current page.

## Input
- `sessionID`: `host:port` (default `localhost:4444`)
- `script`: JS source (required)
- `args`: optional arguments passed to the script
- `async`: use async execution when supported (default false)
- `timeoutMs`: best-effort async timeout
- `destURL`: optional AFS URL to write `{"result": ...}` as JSON (if set, `result` is omitted from the response)


# browserPress

Sends a key press to the focused element resolved by a Playwright-like `locator`, with auto-wait.

## Input
- `sessionID`: `host:port` (default `localhost:4444`)
- `locator`: see `browserFind` locator schema (supports `locator.handle` from `browserFind` when `returnHandles=true`)
- `key`: key name (e.g. `Enter`, `Tab`, `Escape`, `Backspace`, arrows) or raw string
- `timeoutMs`: resolution timeout (default 10000)
- `strict`: require exactly 1 match (default false)
- `visibleOnly`: filter to visible elements (default true)

## Output
- `match`: metadata of the target element (best-effort)

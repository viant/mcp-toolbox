# browserFill

Fills an input/textarea-like element resolved by a Playwright-like `locator`, with auto-wait.

## Input
- `sessionID`: `host:port` (default `localhost:4444`)
- `locator`: see `browserFind` locator schema (supports `locator.handle` from `browserFind` when `returnHandles=true`)
- `text`: text to send
- `clearFirst`: call `Clear()` before typing (default false)
- `timeoutMs`: resolution timeout (default 10000)
- `strict`: require exactly 1 match (default false)
- `visibleOnly`: filter to visible elements (default true)

## Output
- `match`: metadata of the filled element (best-effort)

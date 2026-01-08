# browserHover
Hover (mouse-enter) an element resolved by a Playwright-like `locator`, with auto-wait.

This is useful for UIs where dropdown submenus open on hover / `mouseenter` events.

## Input
- `sessionID`: `host:port` (default `localhost:4444`)
- `locator`: see `browserFind` locator schema (supports `locator.handle`)
- `timeoutMs`: resolution timeout (default 10000)
- `strict`: require exactly 1 match (default false)
- `visibleOnly`: filter to visible elements (default true)

## Output
- `match`: metadata of the hovered element (best-effort)


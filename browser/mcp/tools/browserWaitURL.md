# browserWaitURL
Waits for the current page URL (`window.location.href`) to match.

## Input
- `sessionID`: `host:port` (default `localhost:4444`)
- one of:
  - `exact`: exact URL match
  - `contains`: substring match
  - `regex`: Go regexp match
- `timeoutMs`: total wait time (default 10000)
- `pollMs`: polling interval (default 200)

## Output
- `url`: the matched URL


# browserStorageLoad
Loads a previously saved storage state JSON into the current browser session (cookies + storage).

Notes:
- WebDriver typically requires being on a compatible domain before `AddCookie` succeeds. Use `url` to navigate first.

## Input
- `sessionID`: `host:port` (default `localhost:4444`)
- `sourceURL`: AFS URL to read JSON from (e.g. `file:///tmp/state.json`)
- `url`: optional URL to navigate before applying state

## Output
- `cookies`: number of cookies successfully applied


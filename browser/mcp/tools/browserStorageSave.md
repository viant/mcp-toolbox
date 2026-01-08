# browserStorageSave
Saves the current browser session storage state to a JSON file (cookies + optional local/session storage).

## Input
- `sessionID`: `host:port` (default `localhost:4444`)
- `destURL`: AFS URL to write JSON to (e.g. `file:///tmp/state.json`)
- `includeLocalStorage`: include `window.localStorage` (default false)
- `includeSessionStorage`: include `window.sessionStorage` (default false)

## Output
- `destURL`: where JSON was written
- `bytes`: JSON byte size


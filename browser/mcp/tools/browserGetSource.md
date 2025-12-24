# browserGetSource (alias: webdriverGetSource)

Returns the current page source HTML (`driver.PageSource()`).

If `destURL` is set, writes HTML via `viant/afs` (e.g. `file:///tmp/source.html`).

## Input
- `sessionID`: `host:port` (default `localhost:4444`)
- `destURL`: optional AFS URL for output
- `maxBytes`: optional truncation limit


# browserGetDOM (alias: webdriverGetDOM)

Returns DOM for the current page.

## Modes
- `format: "outerHTML"` (default): returns `document.documentElement.outerHTML` (works on Chrome/Firefox).
- `format: "snapshot"`: Chrome/Edge only; returns CDP `DOMSnapshot.captureSnapshot` (large, structured).

If `destURL` is set:
- `outerHTML`: writes HTML to `destURL`
- `snapshot`: writes JSON to `destURL`

## Input
- `sessionID`: `host:port` (default `localhost:4444`)
- `format`: `outerHTML` | `snapshot`
- `destURL`: optional AFS URL for output
- `maxBytes`: optional truncation limit for `outerHTML`


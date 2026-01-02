# `saveClipboard`

Saves clipboard content to a file (`destURL` via `viant/afs`). If `destURL` is empty, uses a temp `file://...` path based on detected mime type.

Input:
```json
{ "destURL": "file:///tmp/clip.png", "format": "auto" }
```

Formats:
- `auto` (prefers `image/png`, then `text/html`, then `text/plain`)
- `image`
- `html`
- `text`


# `readClipboard`

Reads clipboard content in `text/plain`, `text/html`, or `image/png` (best-effort; full support is macOS-only today).

Input:
```json
{ "format": "auto" }
```

Output:
```json
{ "result": { "mimeType": "text/plain", "text": "..." } }
```

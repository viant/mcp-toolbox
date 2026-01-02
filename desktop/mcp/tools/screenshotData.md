# `screenshotData`

Captures a PNG screenshot and returns it inline as base64.

Prefer `screenshot` for normal use.

Input:
```json
{ "rect": { "x": 0, "y": 0, "w": 800, "h": 600 } }
```

Output:
```json
{ "result": { "encoding": "base64", "data": "iVBORw0KGgo...", "bytes": 12345 } }
```

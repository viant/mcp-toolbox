# `screenshot`

Captures a PNG screenshot and writes it to `destURL` (defaults to a `file://...` temp location when empty).

Input:
```json
{ "destURL": "file:///tmp/screen.png", "rect": { "x": 0, "y": 0, "w": 800, "h": 600 } }
```

Output:
```json
{ "result": { "destURL": "file:///tmp/screen.png", "bytes": 12345 } }
```

# `windowBounds`

Gets window bounds (or client bounds) by PID or handle.

Input:
```json
{ "target": { "kind": "pid", "id": 123 }, "client": false }
```

Output:
```json
{ "result": { "bounds": { "x": 0, "y": 0, "w": 800, "h": 600 } } }
```


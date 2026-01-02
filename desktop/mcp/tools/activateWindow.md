# `activateWindow`

Activates/focuses a window by PID or handle.

Input:
```json
{ "target": { "kind": "pid", "id": 123 } }
```

Or by handle (Windows HWND / X11 XID):
```json
{ "target": { "kind": "handle", "id": 305419896 } }
```


# `listWindows`

Lists candidate top-level windows (best-effort).

This implementation enumerates processes and uses RobotGo to query window title/bounds for each PID. On Windows it also returns `handle` (HWND) when available.

Input:
```json
{
  "titleContains": "Chrome",
  "limit": 50,
  "includeEmptyTitle": false
}
```

Output:
```json
{
  "result": {
    "activePid": 123,
    "windows": [
      {
        "pid": 123,
        "handle": 0,
        "title": "Google Chrome",
        "bounds": { "x": 0, "y": 0, "w": 1440, "h": 900 },
        "active": true
      }
    ]
  }
}
```

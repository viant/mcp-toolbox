# `startProcess`

Starts a local process (e.g. launching an app or running a command).

Input:
```json
{
  "command": "open",
  "args": ["-a", "Calculator"],
  "cwd": "",
  "env": {},
  "wait": false,
  "timeoutMs": 0
}
```

Output:
```json
{
  "result": {
    "pid": 12345,
    "started": true,
    "exitCode": 0,
    "output": ""
  }
}
```

Notes:
- If `wait=false`, the server returns after starting and only guarantees `pid`/`started`.
- If `wait=true`, it waits for process exit and returns `exitCode` + combined `output`.


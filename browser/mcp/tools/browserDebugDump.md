# browserDebugDump

Returns a debug bundle for the current session (DOM/source + capture console/network if enabled).

Input:
```json
{
  "sessionID": "localhost:4444",
  "includeDOM": true,
  "includeSource": false,
  "includeConsole": true,
  "includeNetwork": true,
  "maxEntries": 500,
  "maxBytes": 2000000
}
```


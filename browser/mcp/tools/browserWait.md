# browserWait

Waits for an element state using a Playwright-like locator.

States:
- `visible` (default): at least one match is visible
- `attached`: at least one match exists in DOM (visibility ignored)
- `hidden`: a match exists but is not visible
- `detached`: no matches exist in DOM

Input:
```json
{
  "sessionID": "localhost:4444",
  "locator": { "text": "Chat", "exact": true },
  "state": "visible",
  "timeoutMs": 10000,
  "pollMs": 200
}
```

Output:
```json
{
  "result": {
    "sessionID": "localhost:4444",
    "state": "visible",
    "match": { "selector": "...", "handle": "h1" }
  }
}
```


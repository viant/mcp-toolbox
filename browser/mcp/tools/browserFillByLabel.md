# browserFillByLabel

Convenience tool for filling a textbox by its accessible name/label (maps to `role=textbox name=...`).

Input:
```json
{
  "sessionID": "localhost:4444",
  "label": "Email",
  "text": "me@example.com",
  "exact": true,
  "clearFirst": true,
  "timeoutMs": 10000
}
```


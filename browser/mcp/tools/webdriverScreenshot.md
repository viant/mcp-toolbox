# browserScreenshot (alias: webdriverScreenshot)

Captures a browser screenshot as PNG.

Supports:
- viewport screenshot (default)
- element screenshot (via `selector`)
- full-page best-effort screenshot (Chrome/Edge only via CDP)

This tool always writes the PNG via `viant/afs` (primary sink: `file://...`) and returns only `destURL` (no inline base64).
If `destURL` is empty, it defaults to a `file://` location under the system temp dir.

To get inline base64 instead, use `browserScreenshotData`.

Input:
```json
{
  "sessionID": "localhost:4444",
  "destURL": "file:///tmp/screenshot.png",
  "fullPage": false,
  "selector": {
    "by": "css selector",
    "value": "body"
  },
  "scrollIntoView": true,
  "maxWaitMs": 10000
}
```

Output:
```json
{
  "result": {
    "sessionID": "localhost:4444",
    "destURL": "file:///tmp/screenshot.png",
    "bytes": 12345
  }
}
```

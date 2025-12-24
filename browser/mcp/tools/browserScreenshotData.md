# browserScreenshotData (alias: webdriverScreenshotData)

Captures a browser screenshot as PNG and returns it inline as base64.

Use this only for small screenshots; for normal operation prefer `browserScreenshot` which writes to a file and returns only `destURL`.

## Input
- Same as `browserScreenshot`, but leave `destURL` empty to return base64.


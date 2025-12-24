# browserCallElement (alias: webdriverCallElement)

Finds an element then calls a WebElement method by name (reflection proxy).

## Input
- `sessionID`: `host:port`
- `selector`: `{ by, value, key }` (or put selector string into `value`)
- `call`: `{ method, parameters, waitTimeMs, exit, ... }`

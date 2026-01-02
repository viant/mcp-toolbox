# browserOpen (alias: webdriverOpen)

Opens a WebDriver session and launches a browser.

## Input
- `sessionID`: `host:port` (default `localhost:4444`)
- `browser`: `chrome` | `firefox` (optional)
- `capabilities`: list of args (e.g. `--headless=new`)
- `remote`: optional remote URL (defaults to `http://host:port/wd/hub`)
- `url`: optional URL to navigate to immediately after open
- `navigation`: optional navigation guard options (same shape as `browserRun` navigation)

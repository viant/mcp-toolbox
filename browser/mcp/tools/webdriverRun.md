# browserRun (alias: webdriverRun)

Runs a sequence of webdriver commands using Endly-compatible command syntax.

## Input
- `sessionID`: `host:port` (default `localhost:4444`)
- `commands`: list of command strings or wait-maps
- `navigation`: options for `get(url)` guard (timeout/autoscroll/network-idle)
- `actionDelaysMs`: optional delay between actions

### Command syntax
`[RESULT_KEY=] [(SELECTOR).]METHOD(PARAMS)`

Examples:
- `get(http://example.com)`
- `(#name).sendKeys('hello')`
- `stdout = (.stdout).text`

### Wait map
```json
{"command":"stdout = (.stdout).text","exit":"$stdout.Text:/Hello/","waitTimeMs":60000,"repeat":10}
```

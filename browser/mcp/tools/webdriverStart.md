# browserStart (alias: webdriverStart)

Starts a local WebDriver service (`chromedriver` or `geckodriver`) on a port.
If the driver binary is missing, it is auto-downloaded into the configured install directory.

## Input
- `driver`: `chromedriver` | `geckodriver` (default `chromedriver`)
- `port`: listen port (default `4444`)
- `capabilities`: optional browser args (applied on `webdriverOpen`)

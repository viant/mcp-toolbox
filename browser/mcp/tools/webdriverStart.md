# browserStart (alias: webdriverStart)

Starts a local WebDriver service (`chromedriver` or `geckodriver`) on a port.
If the driver binary is missing, it is auto-downloaded into the configured install directory.

## Output
- `driverPath`: path to the driver binary
- `driverVersion`: best-effort driver version string (for chromedriver)

## Input
- `driver`: `chromedriver` | `geckodriver` (default `chromedriver`)
- `port`: listen port (default `4444`)
- `capabilities`: optional browser args (applied on `webdriverOpen`)

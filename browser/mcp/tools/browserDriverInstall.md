# browserDriverInstall

Installs a WebDriver binary (`chromedriver` or `geckodriver`) into `installDir`.

This is useful when you want to pre-provision `/opt/local/webdriver` or upgrade drivers without manually downloading archives.

## Input
- `driver`: `chromedriver` | `geckodriver` (default `chromedriver`)
- `installDir`: target folder (default: service install dir)
- `force`: re-download even if the binary exists (default false)

## Notes
- For `chromedriver`, the service best-effort detects installed Chrome/Chromium major version and installs/updates the matching Chrome-for-Testing driver (unless `browser-mcp` was started with `--no-match-chrome-driver`).

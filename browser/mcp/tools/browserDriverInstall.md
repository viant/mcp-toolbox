# browserDriverInstall

Installs a WebDriver binary (`chromedriver` or `geckodriver`) into `installDir`.

This is useful when you want to pre-provision `/opt/local/webdriver` or upgrade drivers without manually downloading archives.

## Input
- `driver`: `chromedriver` | `geckodriver` (default `chromedriver`)
- `installDir`: target folder (default: service install dir)
- `version`:
  - chromedriver: `"143.0.1234.5"` (full), `"143"` (major), or `"stable"`/`"latest"`
  - geckodriver: `"v0.34.0"` (or `"0.34.0"`)
- `force`: re-download even if the binary exists (default false)


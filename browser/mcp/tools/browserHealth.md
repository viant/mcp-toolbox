# browserHealth

Reports health for known WebDriver sessions and their driver endpoints.

## Input
- `includeAll`: when true, includes sessions that exist but are not currently open.

## Output
- `sessions[]`: for each known session
  - `sessionID`: `host:port`
  - `open`: whether a WebDriver is currently connected
  - `driverStatus`: `healthy` | `unreachable` | `unknown`
  - `remote`: WebDriver remote URL (if known)
  - `driverPath`, `driverVersion`
  - `warnings[]`: optional diagnostic messages

Use this to verify the local driver service on a given port before opening or restarting sessions.


# IP Lookup MCP

`iplookup-mcp` provides IP geolocation lookup using MaxMind MMDB files.

## 1) Download a city MMDB (open-source test DB)

```bash
mkdir -p ./iplookup/data
curl -fL "https://raw.githubusercontent.com/oschwald/geoip2-golang/main/test-data/GeoIP2-City-Test.mmdb" \
  -o ./iplookup/data/GeoIP2-City-Test.mmdb
```

## 2) Configure environment variables

City DB is required:

```bash
export IPLOOKUP_CITY_MMDB_PATH="$PWD/iplookup/data/GeoIP2-City-Test.mmdb"
```

ISP DB is optional:

```bash
export IPLOOKUP_ISP_MMDB_PATH="/path/to/GeoIP2-ISP.mmdb"
```

If you have local iplookup assets, you can point to those instead:

```bash
export IPLOOKUP_CITY_MMDB_PATH="/opt/iplookup/data/geo/GeoIP2-City.mmdb"
export IPLOOKUP_ISP_MMDB_PATH="/opt/iplookup/data/geo/GeoIP2-ISP.mmdb"
```

## 3) Start the service

```bash
go run ./iplookup/cmd/iplookup-mcp -a 127.0.0.1:5090
```

MCP streamable endpoint:

- `http://127.0.0.1:5090/mcp`

Disable HTTP server:

```bash
go run ./iplookup/cmd/iplookup-mcp -a disabled
```

## 4) Run basic e2e test (optional)

The e2e test uses this resolution order for city MMDB:
1. `IPLOOKUP_E2E_CITY_MMDB`
2. `/opt/iplookup/data/geo/GeoIP2-City.mmdb`
3. Download URL from `IPLOOKUP_E2E_CITY_URL` (or default open-source URL)

Fallback note:
- If `IPLOOKUP_E2E_CITY_MMDB` is set, it takes precedence over the default path.
- If no local file exists, the test downloads the city MMDB automatically.

```bash
MCP_IPLOOKUP_E2E=1 GOCACHE="$PWD/.gocache" go test ./iplookup/service -run Test_E2E_Lookup_WithLocalOrDownloadedMMDB -v
```

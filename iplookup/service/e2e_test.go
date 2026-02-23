package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	defaultCityDBURL = "https://raw.githubusercontent.com/oschwald/geoip2-golang/main/test-data/GeoIP2-City-Test.mmdb"
)

// Test_E2E_Lookup_WithLocalOrDownloadedMMDB runs a basic real lookup against an MMDB file.
//
// Resolution order:
//  1. IPLOOKUP_E2E_CITY_MMDB (if set)
//  2. /opt/iplookup/data/geo/GeoIP2-City.mmdb
//  3. Download an open-source test MMDB.
func Test_E2E_Lookup_WithLocalOrDownloadedMMDB(t *testing.T) {
	requireIPLookupE2E(t)

	cityPath, err := resolveCityMMDB(t)
	require.NoError(t, err)

	svc, err := New(&Config{CityMMDBPath: cityPath})
	require.NoError(t, err)
	defer func() { _ = svc.Close() }()

	results := svc.Lookup(context.Background(), []Query{{IP: "81.2.69.142"}})
	require.Len(t, results, 1)
	require.Nil(t, results[0].Error, "lookup failed: %+v", results[0].Error)
	require.NotNil(t, results[0].Geo, "geo payload was nil")
	require.NotEmpty(t, results[0].Geo.CountryCode, "country code should be populated")
}

func requireIPLookupE2E(t *testing.T) {
	t.Helper()
	if os.Getenv("MCP_LOCAL_TESTS") == "" && os.Getenv("MCP_IPLOOKUP_E2E") == "" {
		t.Skip("set MCP_LOCAL_TESTS=1 or MCP_IPLOOKUP_E2E=1 to run iplookup e2e tests")
	}
}

func resolveCityMMDB(t *testing.T) (string, error) {
	t.Helper()

	target := filepath.Join(t.TempDir(), "city.mmdb")
	for _, candidate := range cityMMDBCandidates() {
		if candidate == "" {
			continue
		}
		if _, err := os.Stat(candidate); err == nil {
			if err := copyFile(candidate, target); err != nil {
				return "", fmt.Errorf("failed to copy %s: %w", candidate, err)
			}
			t.Logf("using local city mmdb from %s", candidate)
			return target, nil
		}
	}

	downloadURL := strings.TrimSpace(os.Getenv("IPLOOKUP_E2E_CITY_URL"))
	if downloadURL == "" {
		downloadURL = defaultCityDBURL
	}
	if err := downloadFile(downloadURL, target); err != nil {
		return "", fmt.Errorf("failed to download city mmdb from %s: %w", downloadURL, err)
	}
	t.Logf("downloaded city mmdb from %s", downloadURL)
	return target, nil
}

func cityMMDBCandidates() []string {
	var result []string
	if fromEnv := strings.TrimSpace(os.Getenv("IPLOOKUP_E2E_CITY_MMDB")); fromEnv != "" {
		result = append(result, fromEnv)
	}
	result = append(result,
		"/opt/iplookup/data/geo/GeoIP2-City.mmdb",
	)
	return result
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

func downloadFile(url, dst string) error {
	client := &http.Client{Timeout: 90 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %s", resp.Status)
	}

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return err
	}
	return out.Sync()
}

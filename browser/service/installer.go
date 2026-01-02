package service

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Defaults mirrored from Endly deployment metadata (pinned versions).
const (
	defaultChromeForTestingVersion = "125.0.6422.76"
	defaultGeckoDriverVersion      = "v0.23.0"
)

func ensureDriverAvailable(ctx context.Context, installDir string, driver string) (string, error) {
	path, _, _, _, err := ensureDriverAvailableWithOptions(ctx, installDir, driver, "", false)
	return path, err
}

var chromeForTestingBaseURL = "https://googlechromelabs.github.io/chrome-for-testing"
var chromeForTestingFetch = fetchChromeForTestingVersion

func ensureDriverAvailableWithOptions(ctx context.Context, installDir string, driver string, version string, force bool) (path string, usedVersion string, artifactURL string, downloaded bool, err error) {
	if installDir == "" {
		return "", "", "", false, fmt.Errorf("installDir was empty")
	}
	driver = strings.ToLower(strings.TrimSpace(driver))
	if driver != ChromeDriver && driver != GeckoDriver {
		return "", "", "", false, fmt.Errorf("unsupported driver: %s", driver)
	}
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return "", "", "", false, err
	}
	dest := filepath.Join(installDir, driver)
	if !force {
		if info, err := os.Stat(dest); err == nil && info.Mode().IsRegular() {
			return dest, "", "", false, nil
		}
	}

	artifactURL, innerPath, usedVersion, err := artifactForVersion(ctx, runtime.GOOS, runtime.GOARCH, driver, version, force)
	if err != nil {
		return "", "", "", false, err
	}
	tmp, err := os.CreateTemp("", "mcp-webdriver-*")
	if err != nil {
		return "", "", "", false, err
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpPath)

	if err := download(ctx, artifactURL, tmpPath); err != nil {
		return "", "", "", false, err
	}

	switch {
	case strings.HasSuffix(artifactURL, ".zip"):
		if err := extractZipFile(tmpPath, innerPath, dest); err != nil {
			return "", "", "", false, err
		}
	case strings.HasSuffix(artifactURL, ".tar.gz"):
		if err := extractTarGzFile(tmpPath, innerPath, dest); err != nil {
			return "", "", "", false, err
		}
	default:
		return "", "", "", false, fmt.Errorf("unsupported archive: %s", artifactURL)
	}

	_ = os.Chmod(dest, 0o755)
	return dest, usedVersion, artifactURL, true, nil
}

func artifactFor(goos, goarch, driver string) (url string, innerPath string, err error) {
	url, innerPath, _, err = artifactForVersion(context.Background(), goos, goarch, driver, "", false)
	return url, innerPath, err
}

func artifactForVersion(ctx context.Context, goos, goarch, driver string, version string, force bool) (url string, innerPath string, usedVersion string, err error) {
	switch driver {
	case ChromeDriver:
		v, err := resolveChromeForTestingVersion(ctx, version, force)
		if err != nil {
			return "", "", "", err
		}
		usedVersion = v
		switch goos {
		case "darwin":
			if goarch == "arm64" {
				return fmt.Sprintf("https://storage.googleapis.com/chrome-for-testing-public/%s/mac-arm64/chromedriver-mac-arm64.zip", v), "chromedriver-mac-arm64/chromedriver", usedVersion, nil
			}
			return fmt.Sprintf("https://storage.googleapis.com/chrome-for-testing-public/%s/mac-x64/chromedriver-mac-x64.zip", v), "chromedriver-mac-x64/chromedriver", usedVersion, nil
		case "linux":
			// Endly metadata uses linux64.
			return fmt.Sprintf("https://storage.googleapis.com/chrome-for-testing-public/%s/linux64/chromedriver-linux64.zip", v), "chromedriver-linux64/chromedriver", usedVersion, nil
		default:
			return "", "", "", fmt.Errorf("unsupported OS for chromedriver: %s/%s", goos, goarch)
		}
	case GeckoDriver:
		v := strings.TrimSpace(version)
		if v == "" {
			v = defaultGeckoDriverVersion
		}
		if !strings.HasPrefix(v, "v") {
			v = "v" + v
		}
		usedVersion = v
		switch goos {
		case "darwin":
			return fmt.Sprintf("https://github.com/mozilla/geckodriver/releases/download/%s/geckodriver-%s-macos.tar.gz", v, v), "geckodriver", usedVersion, nil
		case "linux":
			return fmt.Sprintf("https://github.com/mozilla/geckodriver/releases/download/%s/geckodriver-%s-linux64.tar.gz", v, v), "geckodriver", usedVersion, nil
		default:
			return "", "", "", fmt.Errorf("unsupported OS for geckodriver: %s/%s", goos, goarch)
		}
	default:
		return "", "", "", fmt.Errorf("unsupported driver: %s", driver)
	}
}

func resolveChromeForTestingVersion(ctx context.Context, version string, force bool) (string, error) {
	v := strings.TrimSpace(version)
	if v == "" {
		if force {
			v = "stable"
		} else {
			return defaultChromeForTestingVersion, nil
		}
	}
	lower := strings.ToLower(v)
	switch lower {
	case "stable", "latest":
		return chromeForTestingFetch(ctx, chromeForTestingBaseURL+"/LATEST_RELEASE_STABLE")
	}
	// Full version (e.g. 143.0.1234.5)
	if strings.Contains(v, ".") {
		return v, nil
	}
	// Major only (e.g. 143)
	if _, err := strconv.Atoi(v); err != nil {
		return "", fmt.Errorf("invalid chromedriver version: %s", version)
	}
	return chromeForTestingFetch(ctx, fmt.Sprintf("%s/LATEST_RELEASE_%s", chromeForTestingBaseURL, v))
}

func fetchChromeForTestingVersion(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("fetch %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	out := strings.TrimSpace(string(b))
	if out == "" {
		return "", fmt.Errorf("empty version from %s", url)
	}
	return out, nil
}

func download(ctx context.Context, u string, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("download %s: %s", u, resp.Status)
	}
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

func extractZipFile(zipPath, innerPath, dest string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		if strings.TrimPrefix(f.Name, "./") != innerPath {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		out, err := os.Create(dest)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, rc)
		_ = out.Close()
		return err
	}
	return fmt.Errorf("file %s not found in zip", innerPath)
}

func extractTarGzFile(tgzPath, innerName, dest string) error {
	f, err := os.Open(tgzPath)
	if err != nil {
		return err
	}
	defer f.Close()
	gzr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		if name != innerName {
			continue
		}
		out, err := os.Create(dest)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, tr)
		_ = out.Close()
		return err
	}
	return fmt.Errorf("file %s not found in tar.gz", innerName)
}

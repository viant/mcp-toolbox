package service

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var chromeVersionMatcher = regexp.MustCompile(`(?i)(?:chrome|chromium)[^0-9]*([0-9]+)\.`)
var chromedriverVersionMatcher = regexp.MustCompile(`(?i)(?:chromedriver)[^0-9]*([0-9]+)\.`)
var chromedriverFullVersionMatcher = regexp.MustCompile(`(?i)(?:chromedriver)[^0-9]*([0-9]+(?:\.[0-9]+)+)`)

func ensureChromeDriverMatchesInstalledChrome(ctx context.Context, installDir string) (string, error) {
	path, _, _, _, err := ensureChromeDriverMatchesInstalledChromeWithDetails(ctx, installDir, false)
	return path, err
}

func chromedriverMajor(ctx context.Context, driverPath string) (int, bool) {
	out, err := versionOutput(ctx, driverPath)
	if err != nil {
		return 0, false
	}
	return parseMajor(out, chromedriverVersionMatcher)
}

func chromedriverFullVersion(ctx context.Context, driverPath string) (string, bool) {
	out, err := versionOutput(ctx, driverPath)
	if err != nil {
		return "", false
	}
	m := chromedriverFullVersionMatcher.FindStringSubmatch(out)
	if len(m) < 2 {
		return "", false
	}
	v := strings.TrimSpace(m[1])
	if v == "" {
		return "", false
	}
	return v, true
}

func ensureChromeDriverMatchesInstalledChromeWithDetails(ctx context.Context, installDir string, force bool) (path string, usedVersion string, artifactURL string, downloaded bool, err error) {
	if strings.TrimSpace(installDir) == "" {
		return "", "", "", false, fmt.Errorf("installDir was empty")
	}
	major, rawOut, derr := detectInstalledChromeMajor(ctx)
	if derr != nil || major <= 0 {
		path, usedVersion, artifactURL, downloaded, err = ensureDriverAvailableWithOptions(ctx, installDir, ChromeDriver, "", force)
		if err == nil && usedVersion == "" {
			if v, ok := chromedriverFullVersion(ctx, path); ok {
				usedVersion = v
			}
		}
		if err == nil {
			msg := "chromedriver match: could not detect local Chrome; using default chromedriver"
			if usedVersion != "" {
				msg += fmt.Sprintf(" (driver %s)", usedVersion)
			}
			log.Printf("%s", msg)
		}
		return path, usedVersion, artifactURL, downloaded, err
	}
	// We detected a local Chrome major; log it.
	_ = rawOut
	log.Printf("chromedriver match: detected Chrome major %d", major)

	dest := filepath.Join(installDir, ChromeDriver)
	if info, statErr := os.Stat(dest); !force && statErr == nil && info.Mode().IsRegular() {
		if drvMajor, ok := chromedriverMajor(ctx, dest); ok && drvMajor == major {
			if v, ok := chromedriverFullVersion(ctx, dest); ok {
				log.Printf("chromedriver match: using existing chromedriver %s (for Chrome %d)", v, major)
				return dest, v, "", false, nil
			}
			log.Printf("chromedriver match: using existing chromedriver (major %d)", major)
			return dest, strconv.Itoa(major), "", false, nil
		}
		// mismatch -> force update to correct major
		force = true
	}

	path, usedVersion, artifactURL, downloaded, err = ensureDriverAvailableWithOptions(ctx, installDir, ChromeDriver, strconv.Itoa(major), force)
	if err == nil && usedVersion == "" {
		if v, ok := chromedriverFullVersion(ctx, path); ok {
			usedVersion = v
		}
	}
	if err == nil {
		if downloaded {
			if usedVersion != "" {
				log.Printf("chromedriver match: downloaded chromedriver %s for Chrome %d", usedVersion, major)
			} else {
				log.Printf("chromedriver match: downloaded chromedriver for Chrome %d", major)
			}
		} else {
			if usedVersion != "" {
				log.Printf("chromedriver match: prepared chromedriver %s for Chrome %d", usedVersion, major)
			} else {
				log.Printf("chromedriver match: prepared chromedriver for Chrome %d", major)
			}
		}
	}
	return path, usedVersion, artifactURL, downloaded, err
}

func detectInstalledChromeMajor(ctx context.Context) (major int, raw string, err error) {
	for _, candidate := range chromeCandidates() {
		path := candidate
		if !filepath.IsAbs(path) {
			if resolved, lookErr := exec.LookPath(path); lookErr == nil {
				path = resolved
			} else {
				continue
			}
		}
		out, err := versionOutput(ctx, path)
		if err != nil {
			continue
		}
		major, ok := parseMajor(out, chromeVersionMatcher)
		if ok && major > 0 {
			return major, out, nil
		}
	}
	return 0, "", fmt.Errorf("unable to detect installed Chrome/Chromium version")
}

func chromeCandidates() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"google-chrome",
			"google-chrome-stable",
			"chromium",
			"chromium-browser",
		}
	default:
		return []string{
			"google-chrome",
			"google-chrome-stable",
			"chrome",
			"chromium",
			"chromium-browser",
		}
	}
}

func versionOutput(ctx context.Context, bin string) (string, error) {
	if strings.TrimSpace(bin) == "" {
		return "", fmt.Errorf("binary was empty")
	}
	// Keep this best-effort; do not hang startup on a stuck --version call.
	tctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(tctx, bin, "--version")
	b, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	out := strings.TrimSpace(string(b))
	if out == "" {
		return "", fmt.Errorf("empty version output: %s", bin)
	}
	return out, nil
}

func parseMajor(versionOut string, re *regexp.Regexp) (int, bool) {
	versionOut = strings.TrimSpace(versionOut)
	if versionOut == "" || re == nil {
		return 0, false
	}
	m := re.FindStringSubmatch(versionOut)
	if len(m) < 2 {
		return 0, false
	}
	v, err := strconv.Atoi(m[1])
	if err != nil || v <= 0 {
		return 0, false
	}
	return v, true
}

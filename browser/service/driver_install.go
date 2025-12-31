package service

import (
	"context"
	"fmt"
	"strings"
)

func (s *Service) DriverInstall(ctx context.Context, in *DriverInstallInput) (*DriverInstallOutput, error) {
	if in == nil {
		in = &DriverInstallInput{}
	}
	driver := strings.ToLower(strings.TrimSpace(in.Driver))
	if driver == "" {
		driver = ChromeDriver
	}
	installDir := strings.TrimSpace(in.InstallDir)
	if installDir == "" {
		installDir = s.install
	}
	var (
		path        string
		usedVersion string
		artifactURL string
		downloaded  bool
		err         error
	)
	// Keep chromedriver selection environment-driven: auto-match local Chrome/Chromium when enabled.
	if driver == ChromeDriver && s.autoMatchChromeDriver {
		path, usedVersion, artifactURL, downloaded, err = ensureChromeDriverMatchesInstalledChromeWithDetails(ctx, installDir, in.Force)
	} else {
		path, usedVersion, artifactURL, downloaded, err = ensureDriverAvailableWithOptions(ctx, installDir, driver, "", in.Force)
	}
	if err != nil {
		return nil, err
	}
	if driver == ChromeDriver && usedVersion == "" {
		// Fill version info even when not downloaded in this call.
		if v, ok := chromedriverFullVersion(ctx, path); ok {
			usedVersion = v
		}
	}
	if path == "" {
		return nil, fmt.Errorf("empty driver path")
	}
	return &DriverInstallOutput{
		Driver:      driver,
		InstallDir:  installDir,
		DriverPath:  path,
		Version:     usedVersion,
		ArtifactURL: artifactURL,
		Downloaded:  downloaded,
	}, nil
}

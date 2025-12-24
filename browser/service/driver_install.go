package service

import (
	"context"
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
	path, usedVersion, artifactURL, downloaded, err := ensureDriverAvailableWithOptions(ctx, installDir, driver, in.Version, in.Force)
	if err != nil {
		return nil, err
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

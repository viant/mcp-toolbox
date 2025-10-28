package service

import (
    "context"
    "os/exec"
)

// cmdRunner abstracts command execution. It enables unit tests to inject a fake.
type cmdRunner interface {
    Run(ctx context.Context, name string, args ...string) error
}

type defaultCmdRunner struct{}

func (defaultCmdRunner) Run(ctx context.Context, name string, args ...string) error {
    cmd := exec.CommandContext(ctx, name, args...)
    return cmd.Run()
}

// SetCmdRunner allows tests to inject a custom runner.
func (s *Service) SetCmdRunner(r cmdRunner) { s.runner = r }


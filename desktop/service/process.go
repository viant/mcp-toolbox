package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func (s *Service) StartProcess(ctx context.Context, in *StartProcessInput) (*StartProcessOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("missing input")
	}
	command := strings.TrimSpace(in.Command)
	if command == "" {
		return nil, fmt.Errorf("command is required")
	}

	if in.TimeoutMs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(in.TimeoutMs)*time.Millisecond)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, command, in.Args...)
	if in.Cwd != "" {
		cmd.Dir = in.Cwd
	}
	if len(in.Env) > 0 {
		cmd.Env = append(os.Environ(), envMapToList(in.Env)...)
	}

	var (
		combined  []byte
		runErr    error
		startErr  error
		exitCode  int
		waitState *os.ProcessState
	)
	if err := s.withTimings(in.Timing, func() error {
		if !in.Wait {
			startErr = cmd.Start()
			return nil
		}
		combined, runErr = cmd.CombinedOutput()
		waitState = cmd.ProcessState
		return nil
	}); err != nil {
		return nil, err
	}
	if startErr != nil {
		return nil, startErr
	}
	if runErr != nil && !in.Wait {
		return nil, runErr
	}

	out := &StartProcessOutput{Started: true}
	if cmd.Process != nil {
		out.Pid = cmd.Process.Pid
	}
	if in.Wait {
		out.Output = string(combined)
		if waitState != nil {
			exitCode = waitState.ExitCode()
		} else if runErr != nil {
			exitCode = 1
		}
		out.ExitCode = exitCode
		// If the process failed for reasons other than a non-zero exit code, surface that.
		// (For non-zero exit codes, callers can inspect exitCode + output.)
		if runErr != nil {
			if _, ok := runErr.(*exec.ExitError); !ok {
				return nil, runErr
			}
		}
	}
	return out, nil
}

func envMapToList(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, fmt.Sprintf("%s=%s", k, v))
	}
	return out
}

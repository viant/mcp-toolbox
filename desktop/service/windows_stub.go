//go:build !windows
// +build !windows

package service

import (
	"context"
	"fmt"
)

func (s *Service) SetForegroundWindow(_ context.Context, _ *SetForegroundWindowInput) (*SetForegroundWindowOutput, error) {
	return nil, fmt.Errorf("setForegroundWindow is only supported on windows")
}

func (s *Service) SendWindowMsg(_ context.Context, _ *SendWindowMsgInput) (*SendWindowMsgOutput, error) {
	return nil, fmt.Errorf("sendWindowMsg is only supported on windows")
}

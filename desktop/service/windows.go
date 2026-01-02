//go:build windows
// +build windows

package service

import (
	"context"
	"fmt"

	"github.com/go-vgo/robotgo"
	"github.com/tailscale/win"
)

func (s *Service) SetForegroundWindow(_ context.Context, in *SetForegroundWindowInput) (*SetForegroundWindowOutput, error) {
	if in == nil || in.HWND == 0 {
		return nil, fmt.Errorf("hwnd is required")
	}
	ok := robotgo.SetForeg(win.HWND(uintptr(in.HWND)))
	return &SetForegroundWindowOutput{OK: ok}, nil
}

func (s *Service) SendWindowMsg(_ context.Context, in *SendWindowMsgInput) (*SendWindowMsgOutput, error) {
	if in == nil || in.HWND == 0 {
		return nil, fmt.Errorf("hwnd is required")
	}
	r := robotgo.SendMsg(win.HWND(uintptr(in.HWND)), in.Msg, uintptr(in.WParam), uintptr(in.LParam))
	return &SendWindowMsgOutput{Result: uint64(r)}, nil
}

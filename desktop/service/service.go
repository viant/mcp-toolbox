package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"image"
	"image/png"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/go-vgo/robotgo"
	"github.com/viant/afs"
)

type Service struct {
	useText          bool
	fs               afs.Service
	mux              sync.Mutex
	defaultDisplayID int
}

func NewService(cfg *Config) *Service {
	if cfg == nil {
		cfg = &Config{}
	}
	return &Service{
		useText:          !cfg.UseData,
		fs:               afs.New(),
		defaultDisplayID: -1,
	}
}

func (s *Service) UseTextField() bool { return s.useText }

func (s *Service) resolveDisplayID(override *int) int {
	if override != nil {
		return *override
	}
	s.mux.Lock()
	defer s.mux.Unlock()
	return s.defaultDisplayID
}

func (s *Service) withTimings(t Timing, fn func() error) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	oldMouse := robotgo.MouseSleep
	oldKey := robotgo.KeySleep
	defer func() {
		robotgo.MouseSleep = oldMouse
		robotgo.KeySleep = oldKey
	}()

	if t.MouseSleepMs != nil {
		robotgo.MouseSleep = *t.MouseSleepMs
	}
	if t.KeySleepMs != nil {
		robotgo.KeySleep = *t.KeySleepMs
	}
	return fn()
}

func (s *Service) Info(_ context.Context, _ *InfoInput) (*InfoOutput, error) {
	w, h := robotgo.GetScreenSize()
	x, y := robotgo.Location()
	scale := robotgo.SysScale()
	return &InfoOutput{
		GOOS:   runtime.GOOS,
		GOARCH: runtime.GOARCH,
		Screen: Size{W: w, H: h},
		Mouse:  Point{X: x, Y: y},
		Scale:  scale,
	}, nil
}

func (s *Service) MouseMove(_ context.Context, in *MouseMoveInput) (*MouseMoveOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("missing input")
	}
	if err := s.withTimings(in.Timing, func() error {
		smooth := false
		if in.Smooth != nil {
			smooth = *in.Smooth
		}
		if in.UseSmooth || smooth {
			low, high := in.Low, in.High
			if low == 0 {
				low = 1.0
			}
			if high == 0 {
				high = 3.0
			}
			delay := in.DelayMs
			if delay <= 0 {
				delay = 1
			}
			robotgo.MoveSmooth(in.X, in.Y, low, high, delay)
		} else {
			robotgo.Move(in.X, in.Y)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	x, y := robotgo.Location()
	return &MouseMoveOutput{Mouse: Point{X: x, Y: y}}, nil
}

func (s *Service) MouseClick(_ context.Context, in *MouseClickInput) (*MouseClickOutput, error) {
	if in == nil {
		in = &MouseClickInput{}
	}
	if in.X != nil && in.Y != nil {
		if err := s.withTimings(in.Timing, func() error {
			robotgo.Move(*in.X, *in.Y)
			return nil
		}); err != nil {
			return nil, err
		}
	}
	btn := in.Button
	if btn == "" {
		btn = "left"
	}

	switch in.Down {
	case "":
		if err := s.withTimings(in.Timing, func() error {
			robotgo.Click(btn, in.Double)
			return nil
		}); err != nil {
			return nil, err
		}
	case "down":
		if err := s.withTimings(in.Timing, func() error { return robotgo.Toggle(btn) }); err != nil {
			return nil, err
		}
	case "up":
		if err := s.withTimings(in.Timing, func() error { return robotgo.Toggle(btn, "up") }); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid down value: %q (expected \"\", \"down\", \"up\")", in.Down)
	}

	x, y := robotgo.Location()
	return &MouseClickOutput{Mouse: Point{X: x, Y: y}}, nil
}

func (s *Service) Scroll(_ context.Context, in *ScrollInput) (*ScrollOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("missing input")
	}
	if err := s.withTimings(in.Timing, func() error {
		delay := in.DelayMs
		if delay <= 0 {
			robotgo.Scroll(in.X, in.Y)
		} else {
			robotgo.Scroll(in.X, in.Y, delay)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return &ScrollOutput{}, nil
}

func (s *Service) KeyTap(_ context.Context, in *KeyTapInput) (*KeyTapOutput, error) {
	if in == nil || in.Key == "" {
		return nil, fmt.Errorf("key is required")
	}
	args := make([]any, 0, 1+len(in.Modifiers))
	if in.Pid != 0 {
		args = append(args, in.Pid)
	}
	for _, m := range in.Modifiers {
		args = append(args, m)
	}
	if err := s.withTimings(in.Timing, func() error { return robotgo.KeyTap(in.Key, args...) }); err != nil {
		return nil, err
	}
	return &KeyTapOutput{}, nil
}

func (s *Service) Type(_ context.Context, in *TypeInput) (*TypeOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("missing input")
	}
	if err := s.withTimings(in.Timing, func() error {
		if in.Pid != 0 {
			robotgo.Type(in.Text, in.Pid)
		} else {
			robotgo.Type(in.Text)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return &TypeOutput{}, nil
}

func (s *Service) Screenshot(ctx context.Context, in *ScreenshotInput) (*ScreenshotOutput, error) {
	if in == nil {
		in = &ScreenshotInput{}
	}
	var img image.Image
	if err := s.withTimings(in.Timing, func() error {
		display := s.resolveDisplayID(in.DisplayID)
		if in.Rect != nil {
			r := in.Rect
			if r.W <= 0 || r.H <= 0 {
				return fmt.Errorf("rect requires positive w/h")
			}
			im, err := robotgo.CaptureImg(r.X, r.Y, r.W, r.H, display)
			if err != nil {
				return err
			}
			img = im
			return nil
		}
		if display != -1 {
			r := robotgo.GetScreenRect(display)
			im, err := robotgo.CaptureImg(r.X, r.Y, r.W, r.H, display)
			if err != nil {
				return err
			}
			img = im
			return nil
		}
		im, err := robotgo.CaptureImg()
		if err != nil {
			return err
		}
		img = im
		return nil
	}); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	pngBytes := buf.Bytes()

	out := &ScreenshotOutput{
		DestURL:   in.DestURL,
		Bytes:     len(pngBytes),
		MimeType:  "image/png",
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if in.DestURL != "" {
		if err := s.fs.Upload(ctx, in.DestURL, 0o644, bytes.NewReader(pngBytes)); err != nil {
			return nil, err
		}
		return out, nil
	}
	out.Encoding = "base64"
	out.Data = base64.StdEncoding.EncodeToString(pngBytes)
	return out, nil
}

func (s *Service) ListWindows(ctx context.Context, in *ListWindowsInput) (*ListWindowsOutput, error) {
	if in == nil {
		in = &ListWindowsInput{}
	}
	limit := in.Limit
	if limit <= 0 {
		limit = 200
	}
	titleNeedle := strings.ToLower(strings.TrimSpace(in.TitleContains))

	activePid := robotgo.GetPid()
	pids, err := robotgo.Pids()
	if err != nil {
		return nil, err
	}

	out := &ListWindowsOutput{ActivePid: activePid}
	for _, pid := range pids {
		if len(out.Windows) >= limit {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		title := strings.TrimSpace(robotgo.GetTitle(pid))
		if title == "" && !in.IncludeEmptyTitle {
			continue
		}
		if titleNeedle != "" && !strings.Contains(strings.ToLower(title), titleNeedle) {
			continue
		}

		x, y, w, h := robotgo.GetBounds(pid)
		handle := int64(0)
		if runtime.GOOS == "windows" {
			handle = int64(robotgo.GetHWNDByPid(pid))
		} else if pid == activePid {
			// Best-effort: robotgo exposes a single "current window handle".
			handle = int64(robotgo.GetHandle())
		}

		out.Windows = append(out.Windows, WindowInfo{
			Pid:    pid,
			Handle: handle,
			Title:  title,
			Bounds: Rect{X: x, Y: y, W: w, H: h},
			Active: pid == activePid,
		})
	}
	return out, nil
}

func (s *Service) ActivateWindow(_ context.Context, in *ActivateWindowInput) (*ActivateWindowOutput, error) {
	id, isHandle, err := normalizeTarget(in)
	if err != nil {
		return nil, err
	}
	if isHandle {
		// RobotGo uses isPid=1 to indicate "not pid" for some window APIs.
		if err := s.withTimings(Timing{}, func() error { return robotgo.ActivePid(int(id), 1) }); err != nil {
			return nil, err
		}
		return &ActivateWindowOutput{}, nil
	}
	if err := s.withTimings(Timing{}, func() error { return robotgo.ActivePid(int(id)) }); err != nil {
		return nil, err
	}
	return &ActivateWindowOutput{}, nil
}

func (s *Service) WindowBounds(_ context.Context, in *WindowBoundsInput) (*WindowBoundsOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("missing input")
	}
	id, isHandle, err := normalizeTarget(&ActivateWindowInput{Target: in.Target})
	if err != nil {
		return nil, err
	}
	var (
		x, y, w, h int
	)
	if err := s.withTimings(Timing{}, func() error {
		if in.Client {
			if isHandle {
				x, y, w, h = robotgo.GetClient(int(id), 1)
			} else {
				x, y, w, h = robotgo.GetClient(int(id))
			}
		} else {
			if isHandle {
				x, y, w, h = robotgo.GetBounds(int(id), 1)
			} else {
				x, y, w, h = robotgo.GetBounds(int(id))
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return &WindowBoundsOutput{Bounds: Rect{X: x, Y: y, W: w, H: h}}, nil
}

func (s *Service) MinWindow(_ context.Context, in *WindowStateInput) (*WindowStateOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("missing input")
	}
	id, isHandle, err := normalizeTarget(&ActivateWindowInput{Target: in.Target})
	if err != nil {
		return nil, err
	}
	if err := s.withTimings(Timing{}, func() error {
		if isHandle {
			robotgo.MinWindow(int(id), in.State, 1)
		} else {
			robotgo.MinWindow(int(id), in.State)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return &WindowStateOutput{}, nil
}

func (s *Service) MaxWindow(_ context.Context, in *WindowStateInput) (*WindowStateOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("missing input")
	}
	id, isHandle, err := normalizeTarget(&ActivateWindowInput{Target: in.Target})
	if err != nil {
		return nil, err
	}
	if err := s.withTimings(Timing{}, func() error {
		if isHandle {
			robotgo.MaxWindow(int(id), in.State, 1)
		} else {
			robotgo.MaxWindow(int(id), in.State)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return &WindowStateOutput{}, nil
}

func (s *Service) CloseWindow(_ context.Context, in *CloseWindowInput) (*CloseWindowOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("missing input")
	}
	id, isHandle, err := normalizeTarget(&ActivateWindowInput{Target: in.Target})
	if err != nil {
		return nil, err
	}
	if err := s.withTimings(Timing{}, func() error {
		if isHandle {
			robotgo.CloseWindow(int(id), 1)
		} else {
			robotgo.CloseWindow(int(id))
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return &CloseWindowOutput{}, nil
}

func normalizeTarget(in *ActivateWindowInput) (id int64, isHandle bool, err error) {
	if in == nil {
		return 0, false, fmt.Errorf("missing input")
	}
	kind := strings.ToLower(strings.TrimSpace(in.Target.Kind))
	switch kind {
	case "", "pid":
		if in.Target.ID <= 0 {
			return 0, false, fmt.Errorf("target.id must be > 0 for kind=pid")
		}
		return in.Target.ID, false, nil
	case "handle":
		if in.Target.ID == 0 {
			return 0, false, fmt.Errorf("target.id must be non-zero for kind=handle")
		}
		return in.Target.ID, true, nil
	default:
		return 0, false, fmt.Errorf("unsupported target.kind: %q (expected pid|handle)", in.Target.Kind)
	}
}

func (s *Service) KeyToggle(_ context.Context, in *KeyToggleInput) (*KeyToggleOutput, error) {
	if in == nil || strings.TrimSpace(in.Key) == "" {
		return nil, fmt.Errorf("key is required")
	}
	down := strings.ToLower(strings.TrimSpace(in.Down))
	if down == "" {
		down = "down"
	}
	switch down {
	case "down", "up":
	default:
		return nil, fmt.Errorf("down must be \"down\" or \"up\"")
	}

	var args []any
	if in.Pid != 0 {
		args = append(args, in.Pid)
	}
	args = append(args, down)
	for _, m := range in.Modifiers {
		args = append(args, m)
	}
	if err := s.withTimings(in.Timing, func() error {
		return robotgo.KeyToggle(in.Key, args...)
	}); err != nil {
		return nil, err
	}
	return &KeyToggleOutput{}, nil
}

func (s *Service) MouseToggle(_ context.Context, in *MouseToggleInput) (*MouseToggleOutput, error) {
	if in == nil {
		in = &MouseToggleInput{}
	}
	btn := strings.TrimSpace(in.Button)
	if btn == "" {
		btn = "left"
	}
	down := strings.ToLower(strings.TrimSpace(in.Down))
	if down == "" {
		down = "down"
	}
	switch down {
	case "down":
		return &MouseToggleOutput{}, s.withTimings(in.Timing, func() error { return robotgo.Toggle(btn) })
	case "up":
		return &MouseToggleOutput{}, s.withTimings(in.Timing, func() error { return robotgo.Toggle(btn, "up") })
	default:
		return nil, fmt.Errorf("down must be \"down\" or \"up\"")
	}
}

func (s *Service) DragSmooth(_ context.Context, in *DragSmoothInput) (*DragSmoothOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("missing input")
	}
	btn := strings.TrimSpace(in.Button)
	if btn == "" {
		btn = "left"
	}
	return &DragSmoothOutput{}, s.withTimings(in.Timing, func() error {
		robotgo.Toggle(btn)
		robotgo.DragSmooth(in.X, in.Y)
		return robotgo.Toggle(btn, "up")
	})
}

func (s *Service) MoveRelative(_ context.Context, in *MoveRelativeInput) (*MoveRelativeOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("missing input")
	}
	return &MoveRelativeOutput{}, s.withTimings(in.Timing, func() error {
		robotgo.MoveRelative(in.DX, in.DY)
		return nil
	})
}

func (s *Service) ScrollDir(_ context.Context, in *ScrollDirInput) (*ScrollDirOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("missing input")
	}
	dir := strings.TrimSpace(in.Direction)
	if dir == "" {
		dir = "down"
	}
	return &ScrollDirOutput{}, s.withTimings(in.Timing, func() error {
		robotgo.ScrollDir(in.Amount, dir)
		return nil
	})
}

func (s *Service) ScrollSmooth(_ context.Context, in *ScrollSmoothInput) (*ScrollSmoothOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("missing input")
	}
	num := in.Num
	if num == 0 {
		num = 5
	}
	sleepMs := in.SleepMs
	if sleepMs == 0 {
		sleepMs = 100
	}
	return &ScrollSmoothOutput{}, s.withTimings(in.Timing, func() error {
		if in.ToX != 0 {
			robotgo.ScrollSmooth(in.ToY, num, sleepMs, in.ToX)
			return nil
		}
		robotgo.ScrollSmooth(in.ToY, num, sleepMs)
		return nil
	})
}

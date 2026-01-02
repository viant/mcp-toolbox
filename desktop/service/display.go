package service

import (
	"context"
	"fmt"
	"math"

	"github.com/go-vgo/robotgo"
)

func (s *Service) DisplayInfo(_ context.Context, _ *DisplayInfoInput) (*DisplayInfoOutput, error) {
	mainID := robotgo.GetMainId()
	num := robotgo.DisplaysNum()
	displayID := s.resolveDisplayID(nil)
	scale := robotgo.SysScale(displayID)
	if scale == 0 {
		scale = 1
	}

	rects := make([]Rect, 0, max(0, num))
	for i := 0; i < num; i++ {
		r := robotgo.GetScreenRect(i)
		rects = append(rects, Rect{X: r.X, Y: r.Y, W: r.W, H: r.H})
	}

	return &DisplayInfoOutput{
		DisplayID:   displayID,
		MainID:      mainID,
		NumDisplays: num,
		Scale:       scale,
		Rects:       rects,
	}, nil
}

func (s *Service) SetDisplay(_ context.Context, in *SetDisplayInput) (*SetDisplayOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("missing input")
	}
	s.mux.Lock()
	s.defaultDisplayID = in.DisplayID
	s.mux.Unlock()
	return &SetDisplayOutput{DisplayID: in.DisplayID}, nil
}

func (s *Service) ConvertCoords(_ context.Context, in *ConvertCoordsInput) (*ConvertCoordsOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("missing input")
	}
	factor := in.Factor
	if factor == 0 {
		display := s.resolveDisplayID(in.DisplayID)
		factor = robotgo.SysScale(display)
	}
	if factor == 0 {
		factor = 1
	}

	x, y, w, h := in.X, in.Y, in.W, in.H
	switch in.Mode {
	case "logicalToPhysical":
		x = int(math.Round(float64(x) * factor))
		y = int(math.Round(float64(y) * factor))
		w = int(math.Round(float64(w) * factor))
		h = int(math.Round(float64(h) * factor))
	case "physicalToLogical":
		x = int(math.Round(float64(x) / factor))
		y = int(math.Round(float64(y) / factor))
		w = int(math.Round(float64(w) / factor))
		h = int(math.Round(float64(h) / factor))
	default:
		return nil, fmt.Errorf("unsupported mode: %q", in.Mode)
	}

	return &ConvertCoordsOutput{Factor: factor, X: x, Y: y, W: w, H: h}, nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

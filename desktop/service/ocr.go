//go:build ocr
// +build ocr

package service

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/png"
	"strings"
	"time"

	"github.com/go-vgo/robotgo"
	"github.com/otiai10/gosseract/v2"
)

func (s *Service) FindText(ctx context.Context, in *FindTextInput) (*FindTextOutput, error) {
	if in == nil || strings.TrimSpace(in.Text) == "" {
		return nil, fmt.Errorf("text is required")
	}
	maxResults := in.MaxResults
	if maxResults <= 0 {
		maxResults = 5
	}
	lang := strings.TrimSpace(in.Lang)
	if lang == "" {
		lang = "eng"
	}

	var img image.Image
	if err := s.withTimings(in.Timing, func() error {
		if in.Rect != nil {
			r := in.Rect
			if r.W <= 0 || r.H <= 0 {
				return fmt.Errorf("rect requires positive w/h")
			}
			im, err := robotgo.CaptureImg(r.X, r.Y, r.W, r.H)
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

	client := gosseract.NewClient()
	defer client.Close()
	client.SetLanguage(lang)
	if err := client.SetImageFromBytes(buf.Bytes()); err != nil {
		return nil, err
	}

	boxes, err := client.GetBoundingBoxes(gosseract.RIL_WORD)
	if err != nil {
		return nil, err
	}
	needle := strings.ToLower(strings.TrimSpace(in.Text))

	var out FindTextOutput
	for _, b := range boxes {
		if strings.Contains(strings.ToLower(b.Word), needle) {
			r := Rect{X: b.Box.X, Y: b.Box.Y, W: b.Box.W, H: b.Box.H}
			if in.Rect != nil {
				r.X += in.Rect.X
				r.Y += in.Rect.Y
			}
			out.Boxes = append(out.Boxes, TextBox{Text: b.Word, Rect: r})
			if len(out.Boxes) >= maxResults {
				break
			}
		}
	}
	return &out, nil
}

func (s *Service) ClickText(ctx context.Context, in *ClickTextInput) (*ClickTextOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("missing input")
	}
	ft, err := s.FindText(ctx, &FindTextInput{
		Text:       in.Text,
		Rect:       in.Rect,
		Lang:       in.Lang,
		MaxResults: 1,
		Timing:     in.Timing,
	})
	if err != nil {
		return nil, err
	}
	if len(ft.Boxes) == 0 {
		return &ClickTextOutput{}, fmt.Errorf("no text match found")
	}
	box := ft.Boxes[0]

	if in.DelayMs > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(in.DelayMs) * time.Millisecond):
		}
	}

	btn := strings.TrimSpace(in.Button)
	if btn == "" {
		btn = "left"
	}
	cx := box.Rect.X + box.Rect.W/2
	cy := box.Rect.Y + box.Rect.H/2
	if err := s.withTimings(in.Timing, func() error {
		robotgo.Move(cx, cy)
		robotgo.Click(btn, in.Double)
		return nil
	}); err != nil {
		return nil, err
	}

	return &ClickTextOutput{Box: &box}, nil
}

func (s *Service) ClickTextThenType(ctx context.Context, in *ClickTextThenTypeInput) (*ClickTextThenTypeOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("missing input")
	}
	clicked, err := s.ClickText(ctx, &ClickTextInput{
		Text:    in.Text,
		Rect:    in.Rect,
		Lang:    in.Lang,
		Button:  in.Button,
		Double:  in.Double,
		DelayMs: 0,
		Timing:  in.Timing,
	})
	if err != nil {
		return nil, err
	}
	if in.AfterClickDelayMs > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(in.AfterClickDelayMs) * time.Millisecond):
		}
	}
	if _, err := s.Type(ctx, &TypeInput{Text: in.TypeText, Timing: in.Timing}); err != nil {
		return nil, err
	}
	return &ClickTextThenTypeOutput{Box: clicked.Box}, nil
}

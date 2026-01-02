package service

import (
	"context"
	"image"
	"image/color"
	"testing"
	"time"
)

func TestFindTemplate_Basic(t *testing.T) {
	hay := image.NewRGBA(image.Rect(0, 0, 20, 20))
	for y := 0; y < 20; y++ {
		for x := 0; x < 20; x++ {
			hay.Set(x, y, color.RGBA{R: 0, G: 0, B: 0, A: 255})
		}
	}
	// Draw a white 3x3 block at (7,8)
	for y := 8; y < 11; y++ {
		for x := 7; x < 10; x++ {
			hay.Set(x, y, color.RGBA{R: 255, G: 255, B: 255, A: 255})
		}
	}

	needle := image.NewRGBA(image.Rect(0, 0, 3, 3))
	for y := 0; y < 3; y++ {
		for x := 0; x < 3; x++ {
			needle.Set(x, y, color.RGBA{R: 255, G: 255, B: 255, A: 255})
		}
	}

	matches := findTemplatePyramid(context.Background(), hay, needle, 1, 0.99, 1, time.Time{})
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].X != 7 || matches[0].Y != 8 {
		t.Fatalf("expected match at (7,8), got (%d,%d)", matches[0].X, matches[0].Y)
	}
}

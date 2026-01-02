package service

import (
	"context"
	"fmt"
	"image"
	"image/color"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"math"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-vgo/robotgo"
	"github.com/viant/afs"
)

func (s *Service) GetPixelColor(_ context.Context, in *GetPixelColorInput) (*GetPixelColorOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("missing input")
	}
	display := s.resolveDisplayID(in.DisplayID)
	var hex string
	if err := s.withTimings(in.Timing, func() error {
		c := robotgo.GetPxColor(in.X, in.Y, display)
		h := robotgo.PadHex(c)
		h = strings.TrimSpace(h)
		if h != "" && !strings.HasPrefix(h, "#") {
			h = "#" + h
		}
		hex = h
		return nil
	}); err != nil {
		return nil, err
	}
	return &GetPixelColorOutput{X: in.X, Y: in.Y, Hex: hex}, nil
}

func (s *Service) SamplePixels(ctx context.Context, in *SamplePixelsInput) (*SamplePixelsOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("missing input")
	}
	stepX := in.StepX
	stepY := in.StepY
	if stepX <= 0 {
		stepX = 10
	}
	if stepY <= 0 {
		stepY = 10
	}
	maxSamples := in.MaxSamples
	if maxSamples <= 0 {
		maxSamples = 1000
	}
	display := s.resolveDisplayID(in.DisplayID)
	var samples []PixelSample
	err := s.withTimings(in.Timing, func() error {
		for y := in.Rect.Y; y < in.Rect.Y+in.Rect.H; y += stepY {
			for x := in.Rect.X; x < in.Rect.X+in.Rect.W; x += stepX {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}
				c := robotgo.GetPxColor(x, y, display)
				h := strings.TrimSpace(robotgo.PadHex(c))
				if h != "" && !strings.HasPrefix(h, "#") {
					h = "#" + h
				}
				samples = append(samples, PixelSample{X: x, Y: y, Hex: h})
				if len(samples) >= maxSamples {
					return nil
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &SamplePixelsOutput{Samples: samples}, nil
}

func (s *Service) FindImage(ctx context.Context, in *FindImageInput) (*FindImageOutput, error) {
	if in == nil {
		in = &FindImageInput{}
	}
	if strings.TrimSpace(in.TemplateURL) == "" {
		return nil, fmt.Errorf("templateURL is required")
	}
	step := in.Step
	if step <= 0 {
		step = 1
	}
	maxResults := in.MaxResults
	if maxResults <= 0 {
		maxResults = 1
	}
	threshold := in.Threshold
	if threshold <= 0 {
		threshold = 0.95
	}

	var deadline time.Time
	if in.MaxTimeMs > 0 {
		deadline = time.Now().Add(time.Duration(in.MaxTimeMs) * time.Millisecond)
	}

	fs := afs.New()
	templateImg, err := readImage(ctx, fs, in.TemplateURL)
	if err != nil {
		return nil, err
	}

	var haystack image.Image
	if err := s.withTimings(in.Timing, func() error {
		display := s.resolveDisplayID(in.DisplayID)
		if in.Rect != nil {
			r := in.Rect
			if r.W <= 0 || r.H <= 0 {
				return fmt.Errorf("rect requires positive w/h")
			}
			img, err := robotgo.CaptureImg(r.X, r.Y, r.W, r.H, display)
			if err != nil {
				return err
			}
			haystack = img
			return nil
		}
		if display != -1 {
			r := robotgo.GetScreenRect(display)
			img, err := robotgo.CaptureImg(r.X, r.Y, r.W, r.H, display)
			if err != nil {
				return err
			}
			haystack = img
			return nil
		}
		img, err := robotgo.CaptureImg()
		if err != nil {
			return err
		}
		haystack = img
		return nil
	}); err != nil {
		return nil, err
	}

	matches := findTemplatePyramid(ctx, haystack, templateImg, step, threshold, maxResults, deadline)
	// Offset matches if we searched within a rect.
	if in.Rect != nil {
		for i := range matches {
			matches[i].X += in.Rect.X
			matches[i].Y += in.Rect.Y
		}
	}
	return &FindImageOutput{Matches: matches}, nil
}

func (s *Service) ClickImage(ctx context.Context, in *ClickImageInput) (*ClickImageOutput, error) {
	if in == nil {
		in = &ClickImageInput{}
	}
	findIn := &FindImageInput{
		TemplateURL: in.TemplateURL,
		Rect:        in.Rect,
		DisplayID:   in.DisplayID,
		MaxResults:  1,
		Threshold:   in.Threshold,
		Step:        in.Step,
		MaxTimeMs:   in.MaxTimeMs,
		Timing:      in.Timing,
	}
	out, err := s.FindImage(ctx, findIn)
	if err != nil {
		return nil, err
	}
	if len(out.Matches) == 0 {
		return &ClickImageOutput{}, fmt.Errorf("no match found")
	}
	m := out.Matches[0]
	btn := strings.TrimSpace(in.Button)
	if btn == "" {
		btn = "left"
	}
	cx := m.X + m.W/2
	cy := m.Y + m.H/2
	if err := s.withTimings(in.Timing, func() error {
		robotgo.Move(cx, cy)
		robotgo.Click(btn, in.Double)
		return nil
	}); err != nil {
		return nil, err
	}
	return &ClickImageOutput{Match: &m}, nil
}

func readImage(ctx context.Context, fs afs.Service, url string) (image.Image, error) {
	url = strings.TrimSpace(url)
	if url == "" {
		return nil, fmt.Errorf("empty image url")
	}
	r, err := fs.OpenURL(ctx, url)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	img, _, err := image.Decode(r)
	if err != nil {
		// make common errors more actionable
		ext := strings.ToLower(filepath.Ext(url))
		if ext == "" {
			return nil, fmt.Errorf("failed to decode image (unknown format): %w", err)
		}
		return nil, fmt.Errorf("failed to decode image %s: %w", ext, err)
	}
	return img, nil
}

func findTemplatePyramid(ctx context.Context, haystack image.Image, needle image.Image, step int, threshold float64, maxResults int, deadline time.Time) []ImageMatch {
	if step <= 0 {
		step = 1
	}
	// Build pyramid levels by downscaling by 2 until needle is reasonably small.
	type level struct {
		h  *grayImage
		n  *grayImage
		f  int // scale factor to original pixels (2^level)
		w  int
		hh int
		nw int
		nh int
	}
	var levels []level

	h0 := toGray(haystack)
	n0 := toGray(needle)
	if n0.W <= 0 || n0.H <= 0 || n0.W > h0.W || n0.H > h0.H {
		return nil
	}
	levels = append(levels, level{h: h0, n: n0, f: 1, w: h0.W, hh: h0.H, nw: n0.W, nh: n0.H})

	for f := 2; ; f *= 2 {
		nPrev := levels[len(levels)-1].n
		hPrev := levels[len(levels)-1].h
		if nPrev.W <= 16 || nPrev.H <= 16 {
			break
		}
		nDown := down2(nPrev)
		hDown := down2(hPrev)
		if nDown.W <= 0 || nDown.H <= 0 || nDown.W > hDown.W || nDown.H > hDown.H {
			break
		}
		levels = append(levels, level{h: hDown, n: nDown, f: f, w: hDown.W, hh: hDown.H, nw: nDown.W, nh: nDown.H})
		if f >= 16 {
			break
		}
	}

	// Search from coarsest to finest; keep best candidate and refine.
	var (
		bestX, bestY int
		bestScore    = -1.0
	)

	for li := len(levels) - 1; li >= 0; li-- {
		lv := levels[li]
		s := max(1, step/lv.f)
		// If we already have a candidate from coarser level, search in a small window around it.
		searchX0, searchY0 := 0, 0
		searchX1, searchY1 := lv.w-lv.nw, lv.hh-lv.nh
		if li != len(levels)-1 {
			cx := bestX / lv.f
			cy := bestY / lv.f
			r := 20
			searchX0 = clamp(cx-r, 0, searchX1)
			searchY0 = clamp(cy-r, 0, searchY1)
			searchX1 = clamp(cx+r, 0, searchX1)
			searchY1 = clamp(cy+r, 0, searchY1)
		}

		score, x, y := scanBest(ctx, lv.h, lv.n, s, threshold, searchX0, searchY0, searchX1, searchY1, deadline)
		if score > bestScore {
			bestScore = score
			bestX = x * lv.f
			bestY = y * lv.f
		}
	}

	// Final pass at full res around best candidate to produce matches (up to maxResults).
	final := levels[0]
	x0 := clamp(bestX-50, 0, final.w-final.nw)
	y0 := clamp(bestY-50, 0, final.hh-final.nh)
	x1 := clamp(bestX+50, 0, final.w-final.nw)
	y1 := clamp(bestY+50, 0, final.hh-final.nh)
	return scanAll(ctx, final.h, final.n, step, threshold, maxResults, x0, y0, x1, y1, deadline)
}

type grayImage struct {
	W, H int
	Pix  []uint8
}

func toGray(img image.Image) *grayImage {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	g := &grayImage{W: w, H: h, Pix: make([]uint8, w*h)}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			g.Pix[y*w+x] = luma(img.At(b.Min.X+x, b.Min.Y+y))
		}
	}
	return g
}

func down2(src *grayImage) *grayImage {
	if src.W < 2 || src.H < 2 {
		return src
	}
	w := src.W / 2
	h := src.H / 2
	dst := &grayImage{W: w, H: h, Pix: make([]uint8, w*h)}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			// 2x2 average
			i := (y*2)*src.W + x*2
			a := int(src.Pix[i])
			b := int(src.Pix[i+1])
			c := int(src.Pix[i+src.W])
			d := int(src.Pix[i+src.W+1])
			dst.Pix[y*w+x] = uint8((a + b + c + d) / 4)
		}
	}
	return dst
}

func scanBest(ctx context.Context, hay *grayImage, needle *grayImage, step int, threshold float64, x0, y0, x1, y1 int, deadline time.Time) (bestScore float64, bestX int, bestY int) {
	bestScore = -1
	maxMae := (1.0 - threshold) * 255.0
	if maxMae < 0 {
		maxMae = 0
	}
	allowedSum := maxMae * float64(needle.W*needle.H)
	for y := y0; y <= y1; y += step {
		for x := x0; x <= x1; x += step {
			if !deadline.IsZero() && time.Now().After(deadline) {
				return bestScore, bestX, bestY
			}
			select {
			case <-ctx.Done():
				return bestScore, bestX, bestY
			default:
			}
			score := matchScoreGray(hay, needle, x, y, allowedSum)
			if score > bestScore {
				bestScore = score
				bestX, bestY = x, y
			}
		}
	}
	return bestScore, bestX, bestY
}

func scanAll(ctx context.Context, hay *grayImage, needle *grayImage, step int, threshold float64, maxResults int, x0, y0, x1, y1 int, deadline time.Time) []ImageMatch {
	if step <= 0 {
		step = 1
	}
	maxMae := (1.0 - threshold) * 255.0
	if maxMae < 0 {
		maxMae = 0
	}
	allowedSum := maxMae * float64(needle.W*needle.H)
	var matches []ImageMatch
	for y := y0; y <= y1; y += step {
		for x := x0; x <= x1; x += step {
			if !deadline.IsZero() && time.Now().After(deadline) {
				return matches
			}
			select {
			case <-ctx.Done():
				return matches
			default:
			}
			score := matchScoreGray(hay, needle, x, y, allowedSum)
			if score >= threshold {
				matches = append(matches, ImageMatch{X: x, Y: y, W: needle.W, H: needle.H, Score: score})
				if len(matches) >= maxResults {
					return matches
				}
			}
		}
	}
	return matches
}

func matchScoreGray(hay *grayImage, needle *grayImage, x0, y0 int, allowedSum float64) float64 {
	var sum float64
	for y := 0; y < needle.H; y++ {
		hi := (y0+y)*hay.W + x0
		ni := y * needle.W
		for x := 0; x < needle.W; x++ {
			d := float64(hay.Pix[hi+x]) - float64(needle.Pix[ni+x])
			if d < 0 {
				d = -d
			}
			sum += d
			if allowedSum > 0 && sum > allowedSum {
				return 0
			}
		}
	}
	mae := sum / float64(needle.W*needle.H)
	score := 1.0 - (mae / 255.0)
	if score < 0 {
		return 0
	}
	if score > 1 {
		return 1
	}
	return score
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func matchScore(hay image.Image, x0, y0, w, h int, nGray []uint8) float64 {
	var sum float64
	idx := 0
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			hv := luma(hay.At(x0+x, y0+y))
			nv := nGray[idx]
			idx++
			sum += math.Abs(float64(hv) - float64(nv))
		}
	}
	// Mean absolute error in [0..255]
	mae := sum / float64(w*h)
	// Convert to similarity score in [0..1]
	score := 1.0 - (mae / 255.0)
	if score < 0 {
		return 0
	}
	if score > 1 {
		return 1
	}
	return score
}

func luma(c color.Color) uint8 {
	r, g, b, _ := c.RGBA()
	// r,g,b in [0..65535]
	rr := float64(r) / 257.0
	gg := float64(g) / 257.0
	bb := float64(b) / 257.0
	y := 0.299*rr + 0.587*gg + 0.114*bb
	if y < 0 {
		y = 0
	}
	if y > 255 {
		y = 255
	}
	return uint8(y + 0.5)
}

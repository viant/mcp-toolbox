package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-vgo/robotgo"
)

type runState struct {
	displayID int
}

func (s *Service) Run(ctx context.Context, in *RunInput) (*RunOutput, error) {
	if in == nil {
		in = &RunInput{}
	}
	out := &RunOutput{
		Data:    map[string]any{},
		Actions: make([]RunAction, 0, len(in.Commands)),
	}
	delay := time.Duration(in.ActionDelay) * time.Millisecond

	state := &runState{displayID: s.resolveDisplayID(in.DisplayID)}

	err := s.withTimings(in.Timing, func() error {
		for i, raw := range in.Commands {
			cmdStr := strings.TrimSpace(raw)
			act := RunAction{Index: i, Command: cmdStr}
			if cmdStr == "" {
				act.Error = "empty command"
				out.Actions = append(out.Actions, act)
				continue
			}
			if delay > 0 && i > 0 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(delay):
				}
			}

			cmd, err := parseDSL(cmdStr)
			if err != nil {
				act.Error = err.Error()
				out.Actions = append(out.Actions, act)
				continue
			}

			res, err := s.execDSL(ctx, cmd, state)
			if err != nil {
				act.Error = err.Error()
				out.Actions = append(out.Actions, act)
				continue
			}
			if cmd.Assign != "" {
				out.Data[cmd.Assign] = res
			}
			out.Actions = append(out.Actions, act)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) execDSL(ctx context.Context, cmd *dslCommand, st *runState) (any, error) {
	name := strings.ToLower(cmd.Name)
	switch name {
	case "sleep":
		ms, err := argInt(cmd, 0, "ms", 0)
		if err != nil {
			return nil, err
		}
		if ms < 0 {
			return nil, fmt.Errorf("sleep ms must be >= 0")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(ms) * time.Millisecond):
			return nil, nil
		}

	case "move":
		x, err := argInt(cmd, 0, "x", 0)
		if err != nil {
			return nil, err
		}
		y, err := argInt(cmd, 1, "y", 0)
		if err != nil {
			return nil, err
		}
		robotgo.Move(x, y)
		return map[string]any{"mouse": Point{X: x, Y: y}}, nil

	case "movesmooth":
		x, err := argInt(cmd, 0, "x", 0)
		if err != nil {
			return nil, err
		}
		y, err := argInt(cmd, 1, "y", 0)
		if err != nil {
			return nil, err
		}
		low, high := 1.0, 3.0
		delayMs := 1
		if v, ok := getArg(cmd, 2); ok {
			if f, ok := floatFromAny(v); ok {
				low = f
			}
		}
		if v, ok := getArg(cmd, 3); ok {
			if f, ok := floatFromAny(v); ok {
				high = f
			}
		}
		if v, ok := getArg(cmd, 4); ok {
			if iv, ok := v.(int); ok {
				delayMs = iv
			}
		}
		robotgo.MoveSmooth(x, y, low, high, delayMs)
		return map[string]any{"mouse": Point{X: x, Y: y}}, nil

	case "click":
		button := "left"
		double := false
		if len(cmd.Args) > 0 {
			if s, ok := cmd.Args[0].(string); ok && s != "" {
				button = s
			}
		}
		if len(cmd.Args) > 1 {
			if b, ok := cmd.Args[1].(bool); ok {
				double = b
			}
		}
		if cmd.Kw != nil {
			if v, ok := cmd.Kw["button"].(string); ok && v != "" {
				button = v
			}
			if v, ok := cmd.Kw["double"].(bool); ok {
				double = v
			}
		}
		robotgo.Click(button, double)
		x, y := robotgo.Location()
		return map[string]any{"mouse": Point{X: x, Y: y}}, nil

	case "scroll":
		x, err := argInt(cmd, 0, "x", 0)
		if err != nil {
			return nil, err
		}
		y, err := argInt(cmd, 1, "y", 0)
		if err != nil {
			return nil, err
		}
		delay := 0
		if len(cmd.Args) > 2 {
			if v, ok := cmd.Args[2].(int); ok {
				delay = v
			}
		}
		if cmd.Kw != nil {
			if v, ok := cmd.Kw["delayMs"].(int); ok {
				delay = v
			}
		}
		if delay > 0 {
			robotgo.Scroll(x, y, delay)
		} else {
			robotgo.Scroll(x, y)
		}
		return nil, nil

	case "scrolldir":
		amount, err := argInt(cmd, 0, "amount", 0)
		if err != nil {
			return nil, err
		}
		dir, err := argString(cmd, 1, "dir", "")
		if err != nil {
			return nil, err
		}
		if dir == "" {
			dir = "down"
		}
		robotgo.ScrollDir(amount, dir)
		return nil, nil

	case "keytap":
		key, err := argString(cmd, 0, "key", "")
		if err != nil {
			return nil, err
		}
		if key == "" {
			return nil, fmt.Errorf("keyTap requires key")
		}
		var (
			pid  int
			mods []any
		)
		if cmd.Kw != nil {
			if v, ok := cmd.Kw["pid"].(int); ok {
				pid = v
			}
		}
		for _, a := range cmd.Args[1:] {
			if iv, ok := a.(int); ok && pid == 0 {
				pid = iv
				continue
			}
			mods = append(mods, a)
		}
		var callArgs []any
		if pid != 0 {
			callArgs = append(callArgs, pid)
		}
		for _, m := range mods {
			if s, ok := m.(string); ok && s != "" {
				callArgs = append(callArgs, s)
			}
		}
		if err := robotgo.KeyTap(key, callArgs...); err != nil {
			return nil, err
		}
		return nil, nil

	case "keydown":
		key, err := argString(cmd, 0, "key", "")
		if err != nil {
			return nil, err
		}
		if key == "" {
			return nil, fmt.Errorf("keyDown requires key")
		}
		return nil, robotgo.KeyToggle(key, "down")

	case "keyup":
		key, err := argString(cmd, 0, "key", "")
		if err != nil {
			return nil, err
		}
		if key == "" {
			return nil, fmt.Errorf("keyUp requires key")
		}
		return nil, robotgo.KeyToggle(key, "up")

	case "keytoggle":
		key, err := argString(cmd, 0, "key", "")
		if err != nil {
			return nil, err
		}
		if key == "" {
			return nil, fmt.Errorf("keyToggle requires key")
		}
		down, err := argString(cmd, 1, "down", "down")
		if err != nil {
			return nil, err
		}
		if down == "" {
			down = "down"
		}
		return nil, robotgo.KeyToggle(key, down)

	case "mousetoggle":
		button, err := argString(cmd, 0, "button", "left")
		if err != nil {
			return nil, err
		}
		down, err := argString(cmd, 1, "down", "down")
		if err != nil {
			return nil, err
		}
		if strings.ToLower(down) == "up" {
			return nil, robotgo.Toggle(button, "up")
		}
		return nil, robotgo.Toggle(button)

	case "dragsmooth":
		x, err := argInt(cmd, 0, "x", 0)
		if err != nil {
			return nil, err
		}
		y, err := argInt(cmd, 1, "y", 0)
		if err != nil {
			return nil, err
		}
		button, _ := argString(cmd, 2, "button", "left")
		if button == "" {
			button = "left"
		}
		if err := robotgo.Toggle(button); err != nil {
			return nil, err
		}
		robotgo.DragSmooth(x, y)
		return nil, robotgo.Toggle(button, "up")

	case "moverelative":
		dx, err := argInt(cmd, 0, "dx", 0)
		if err != nil {
			return nil, err
		}
		dy, err := argInt(cmd, 1, "dy", 0)
		if err != nil {
			return nil, err
		}
		robotgo.MoveRelative(dx, dy)
		return nil, nil

	case "scrollsmooth":
		toY, err := argInt(cmd, 0, "toY", 0)
		if err != nil {
			return nil, err
		}
		num, _ := argInt(cmd, 1, "num", 5)
		sleepMs, _ := argInt(cmd, 2, "sleepMs", 100)
		toX, _ := argInt(cmd, 3, "toX", 0)
		if toX != 0 {
			robotgo.ScrollSmooth(toY, num, sleepMs, toX)
			return nil, nil
		}
		robotgo.ScrollSmooth(toY, num, sleepMs)
		return nil, nil

	case "readclipboard":
		s, err := robotgo.ReadAll()
		if err != nil {
			return nil, err
		}
		return s, nil

	case "writeclipboard":
		text, err := argString(cmd, 0, "text", "")
		if err != nil {
			return nil, err
		}
		return nil, robotgo.WriteAll(text)

	case "type":
		text, err := argString(cmd, 0, "text", "")
		if err != nil {
			return nil, err
		}
		if text == "" && cmd.Kw != nil {
			if v, ok := cmd.Kw["text"].(string); ok {
				text = v
			}
		}
		if text == "" {
			return nil, fmt.Errorf("type requires text")
		}
		robotgo.Type(text)
		return nil, nil

	case "screenshot":
		in := &ScreenshotInput{}
		if cmd.Kw != nil {
			if v, ok := cmd.Kw["destURL"].(string); ok {
				in.DestURL = v
			}
			x, _ := cmd.Kw["x"].(int)
			y, _ := cmd.Kw["y"].(int)
			w, _ := cmd.Kw["w"].(int)
			h, _ := cmd.Kw["h"].(int)
			if w > 0 && h > 0 {
				in.Rect = &Rect{X: x, Y: y, W: w, H: h}
			}
			if v, ok := cmd.Kw["displayId"].(int); ok {
				in.DisplayID = &v
			}
		}
		if in.DisplayID == nil && st != nil && st.displayID != -1 {
			v := st.displayID
			in.DisplayID = &v
		}
		if in.DestURL == "" {
			url, err := DefaultScreenshotDestURL()
			if err != nil {
				return nil, err
			}
			in.DestURL = url
		}
		out, err := s.Screenshot(ctx, in)
		if err != nil {
			return nil, err
		}
		out.Encoding = ""
		out.Data = ""
		return out, nil

	case "getpixelcolor":
		x, err := argInt(cmd, 0, "x", 0)
		if err != nil {
			return nil, err
		}
		y, err := argInt(cmd, 1, "y", 0)
		if err != nil {
			return nil, err
		}
		var displayID *int
		if cmd.Kw != nil {
			if v, ok := cmd.Kw["displayId"].(int); ok {
				displayID = &v
			}
		}
		if displayID == nil && st != nil && st.displayID != -1 {
			v := st.displayID
			displayID = &v
		}
		out, err := s.GetPixelColor(ctx, &GetPixelColorInput{X: x, Y: y, DisplayID: displayID})
		if err != nil {
			return nil, err
		}
		return out.Hex, nil

	case "findimage":
		u, err := argString(cmd, 0, "templateURL", "")
		if err != nil {
			return nil, err
		}
		if u == "" {
			u, _ = argString(cmd, 0, "url", "")
		}
		threshold := 0.95
		if cmd.Kw != nil {
			if v, ok := cmd.Kw["threshold"].(float64); ok {
				threshold = v
			}
			if v, ok := cmd.Kw["threshold"].(int); ok {
				threshold = float64(v)
			}
		}
		step := 1
		if cmd.Kw != nil {
			if v, ok := cmd.Kw["step"].(int); ok {
				step = v
			}
		}
		maxResults := 1
		if cmd.Kw != nil {
			if v, ok := cmd.Kw["maxResults"].(int); ok {
				maxResults = v
			}
		}
		var displayID *int
		if cmd.Kw != nil {
			if v, ok := cmd.Kw["displayId"].(int); ok {
				displayID = &v
			}
		}
		if displayID == nil && st != nil && st.displayID != -1 {
			v := st.displayID
			displayID = &v
		}
		out, err := s.FindImage(ctx, &FindImageInput{TemplateURL: u, Threshold: threshold, Step: step, MaxResults: maxResults, DisplayID: displayID})
		if err != nil {
			return nil, err
		}
		return out, nil

	case "clickimage":
		u, err := argString(cmd, 0, "templateURL", "")
		if err != nil {
			return nil, err
		}
		btn, _ := argString(cmd, 1, "button", "left")
		double := false
		if cmd.Kw != nil {
			if v, ok := cmd.Kw["double"].(bool); ok {
				double = v
			}
		}
		threshold := 0.95
		if cmd.Kw != nil {
			if v, ok := cmd.Kw["threshold"].(float64); ok {
				threshold = v
			}
			if v, ok := cmd.Kw["threshold"].(int); ok {
				threshold = float64(v)
			}
		}
		step := 1
		if cmd.Kw != nil {
			if v, ok := cmd.Kw["step"].(int); ok {
				step = v
			}
		}
		var displayID *int
		if cmd.Kw != nil {
			if v, ok := cmd.Kw["displayId"].(int); ok {
				displayID = &v
			}
		}
		if displayID == nil && st != nil && st.displayID != -1 {
			v := st.displayID
			displayID = &v
		}
		out, err := s.ClickImage(ctx, &ClickImageInput{TemplateURL: u, Button: btn, Double: double, Threshold: threshold, Step: step, DisplayID: displayID})
		if err != nil {
			return nil, err
		}
		return out, nil

	case "setdisplay":
		id, err := argInt(cmd, 0, "displayId", 0)
		if err != nil {
			return nil, err
		}
		if st != nil {
			st.displayID = id
		}
		return &SetDisplayOutput{DisplayID: id}, nil

	case "displayinfo":
		out, err := s.DisplayInfo(ctx, &DisplayInfoInput{})
		if err != nil {
			return nil, err
		}
		return out, nil

	case "convertcoords":
		mode, err := argString(cmd, 0, "mode", "")
		if err != nil {
			return nil, err
		}
		x, err := argInt(cmd, 1, "x", 0)
		if err != nil {
			return nil, err
		}
		y, err := argInt(cmd, 2, "y", 0)
		if err != nil {
			return nil, err
		}
		w, _ := argInt(cmd, 3, "w", 0)
		h, _ := argInt(cmd, 4, "h", 0)
		var displayID *int
		if cmd.Kw != nil {
			if v, ok := cmd.Kw["displayId"].(int); ok {
				displayID = &v
			}
		}
		if displayID == nil && st != nil && st.displayID != -1 {
			v := st.displayID
			displayID = &v
		}
		out, err := s.ConvertCoords(ctx, &ConvertCoordsInput{Mode: mode, X: x, Y: y, W: w, H: h, DisplayID: displayID})
		if err != nil {
			return nil, err
		}
		return out, nil

	case "typeintowindow":
		title, err := argString(cmd, 0, "titleContains", "")
		if err != nil {
			return nil, err
		}
		text, err := argString(cmd, 1, "text", "")
		if err != nil {
			return nil, err
		}
		delayMs, _ := argInt(cmd, 2, "delayMs", 200)
		out, err := s.TypeIntoWindow(ctx, &TypeIntoWindowInput{TitleContains: title, Text: text, DelayMs: delayMs})
		if err != nil {
			return nil, err
		}
		return out, nil

	case "findtext":
		text, err := argString(cmd, 0, "text", "")
		if err != nil {
			return nil, err
		}
		lang, _ := argString(cmd, 1, "lang", "eng")
		maxResults, _ := argInt(cmd, 2, "maxResults", 5)
		out, err := s.FindText(ctx, &FindTextInput{Text: text, Lang: lang, MaxResults: maxResults})
		if err != nil {
			return nil, err
		}
		return out, nil

	case "clicktext":
		text, err := argString(cmd, 0, "text", "")
		if err != nil {
			return nil, err
		}
		lang, _ := argString(cmd, 1, "lang", "eng")
		btn, _ := argString(cmd, 2, "button", "left")
		double := false
		if cmd.Kw != nil {
			if v, ok := cmd.Kw["double"].(bool); ok {
				double = v
			}
		}
		delayMs, _ := argInt(cmd, 3, "delayMs", 0)
		out, err := s.ClickText(ctx, &ClickTextInput{Text: text, Lang: lang, Button: btn, Double: double, DelayMs: delayMs})
		if err != nil {
			return nil, err
		}
		return out, nil

	case "clicktextthentype":
		text, err := argString(cmd, 0, "text", "")
		if err != nil {
			return nil, err
		}
		typeText, err := argString(cmd, 1, "typeText", "")
		if err != nil {
			return nil, err
		}
		lang, _ := argString(cmd, 2, "lang", "eng")
		btn, _ := argString(cmd, 3, "button", "left")
		double := false
		if cmd.Kw != nil {
			if v, ok := cmd.Kw["double"].(bool); ok {
				double = v
			}
		}
		afterMs, _ := argInt(cmd, 4, "afterClickDelayMs", 150)
		out, err := s.ClickTextThenType(ctx, &ClickTextThenTypeInput{Text: text, TypeText: typeText, Lang: lang, Button: btn, Double: double, AfterClickDelayMs: afterMs})
		if err != nil {
			return nil, err
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported command: %s", cmd.Name)
	}
}

func getArg(cmd *dslCommand, idx int) (any, bool) {
	if idx < 0 || idx >= len(cmd.Args) {
		return nil, false
	}
	return cmd.Args[idx], true
}

func argInt(cmd *dslCommand, idx int, key string, def int) (int, error) {
	if cmd.Kw != nil {
		if v, ok := cmd.Kw[key]; ok {
			if iv, ok := v.(int); ok {
				return iv, nil
			}
			return 0, fmt.Errorf("%s must be int", key)
		}
	}
	if v, ok := getArg(cmd, idx); ok {
		if iv, ok := v.(int); ok {
			return iv, nil
		}
		return 0, fmt.Errorf("arg %d must be int", idx)
	}
	return def, nil
}

func argString(cmd *dslCommand, idx int, key string, def string) (string, error) {
	if cmd.Kw != nil {
		if v, ok := cmd.Kw[key]; ok {
			if sv, ok := v.(string); ok {
				return sv, nil
			}
			return "", fmt.Errorf("%s must be string", key)
		}
	}
	if v, ok := getArg(cmd, idx); ok {
		if sv, ok := v.(string); ok {
			return sv, nil
		}
		return "", fmt.Errorf("arg %d must be string", idx)
	}
	return def, nil
}

func floatFromAny(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	default:
		return 0, false
	}
}

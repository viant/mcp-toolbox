package service

import (
	"context"
	"fmt"
	"strings"
)

func (s *Service) ClickText(ctx context.Context, in *ClickTextInput) (*ClickTextOutput, error) {
	if in == nil {
		in = &ClickTextInput{}
	}
	if in.SessionID == "" {
		in.SessionID = "localhost:4444"
	}
	text := strings.TrimSpace(in.Text)
	if text == "" {
		return nil, fmt.Errorf("text is required")
	}
	loc := &Locator{Text: text, Exact: in.Exact, Within: in.Within}
	out, err := s.Click(ctx, &ClickInput{
		SessionID:   in.SessionID,
		Locator:     loc,
		TimeoutMs:   in.TimeoutMs,
		Strict:      false,
		VisibleOnly: true,
	})
	if err != nil {
		return nil, err
	}
	return &ClickTextOutput{SessionID: in.SessionID, Match: out.Match}, nil
}

func (s *Service) FillByLabel(ctx context.Context, in *FillByLabelInput) (*FillByLabelOutput, error) {
	if in == nil {
		in = &FillByLabelInput{}
	}
	if in.SessionID == "" {
		in.SessionID = "localhost:4444"
	}
	label := strings.TrimSpace(in.Label)
	if label == "" {
		return nil, fmt.Errorf("label is required")
	}
	loc := &Locator{
		Role:   "textbox",
		Name:   label,
		Exact:  in.Exact,
		Within: in.Within,
	}
	out, err := s.Fill(ctx, &FillInput{
		SessionID:   in.SessionID,
		Locator:     loc,
		Text:        in.Text,
		ClearFirst:  in.ClearFirst,
		TimeoutMs:   in.TimeoutMs,
		Strict:      false,
		VisibleOnly: true,
	})
	if err != nil {
		return nil, err
	}
	return &FillByLabelOutput{SessionID: in.SessionID, Match: out.Match}, nil
}

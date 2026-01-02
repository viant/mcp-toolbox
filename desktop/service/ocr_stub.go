//go:build !ocr
// +build !ocr

package service

import (
	"context"
	"fmt"
)

func (s *Service) FindText(_ context.Context, _ *FindTextInput) (*FindTextOutput, error) {
	return nil, fmt.Errorf("findText requires OCR; build with -tags ocr and ensure tesseract is installed")
}

func (s *Service) ClickText(_ context.Context, _ *ClickTextInput) (*ClickTextOutput, error) {
	return nil, fmt.Errorf("clickText requires OCR; build with -tags ocr and ensure tesseract is installed")
}

func (s *Service) ClickTextThenType(_ context.Context, _ *ClickTextThenTypeInput) (*ClickTextThenTypeOutput, error) {
	return nil, fmt.Errorf("clickTextThenType requires OCR; build with -tags ocr and ensure tesseract is installed")
}

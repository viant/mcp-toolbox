//go:build darwin
// +build darwin

package service

/*
#cgo darwin CFLAGS: -x objective-c
#cgo darwin LDFLAGS: -framework AppKit -framework Foundation
#include <stdlib.h>
#include <string.h>
#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>

static char* pb_read_string(const char* uti) {
	@autoreleasepool {
		NSPasteboard* pb = [NSPasteboard generalPasteboard];
		NSString* t = [NSString stringWithUTF8String:uti];
		NSString* s = [pb stringForType:t];
		if (s == nil) { return NULL; }
		const char* c = [s UTF8String];
		if (c == NULL) { return NULL; }
		return strdup(c);
	}
}

static void* pb_read_data(const char* uti, int* outLen) {
	@autoreleasepool {
		NSPasteboard* pb = [NSPasteboard generalPasteboard];
		NSString* t = [NSString stringWithUTF8String:uti];
		NSData* d = [pb dataForType:t];
		if (d == nil) { *outLen = 0; return NULL; }
		*outLen = (int)[d length];
		if (*outLen <= 0) { return NULL; }
		void* buf = malloc(*outLen);
		if (buf == NULL) { return NULL; }
		memcpy(buf, [d bytes], *outLen);
		return buf;
	}
}

static int pb_write_string(const char* uti, const char* text) {
	@autoreleasepool {
		NSPasteboard* pb = [NSPasteboard generalPasteboard];
		[pb clearContents];
		NSString* t = [NSString stringWithUTF8String:uti];
		NSString* s = [NSString stringWithUTF8String:text];
		if (s == nil) { s = @""; }
		BOOL ok = [pb setString:s forType:t];
		return ok ? 1 : 0;
	}
}

static int pb_write_data(const char* uti, const void* data, int len) {
	@autoreleasepool {
		NSPasteboard* pb = [NSPasteboard generalPasteboard];
		[pb clearContents];
		NSString* t = [NSString stringWithUTF8String:uti];
		NSData* d = [NSData dataWithBytes:data length:len];
		BOOL ok = [pb setData:d forType:t];
		return ok ? 1 : 0;
	}
}
*/
import "C"

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"unsafe"
)

const (
	utiText = "public.utf8-plain-text"
	utiHTML = "public.html"
	utiPNG  = "public.png"
)

func (s *Service) ReadClipboard(_ context.Context, in *ReadClipboardInput) (*ReadClipboardOutput, error) {
	if in == nil {
		in = &ReadClipboardInput{}
	}
	format := strings.ToLower(strings.TrimSpace(in.Format))
	if format == "" {
		format = "auto"
	}

	var (
		mime string
		text string
		data []byte
	)
	if err := s.withTimings(in.Timing, func() error {
		switch format {
		case "auto":
			// Prefer binary/image, then html, then text.
			if b, ok := pbReadData(utiPNG); ok {
				mime = "image/png"
				data = b
				return nil
			}
			if s, ok := pbReadString(utiHTML); ok {
				mime = "text/html"
				text = s
				return nil
			}
			if s, ok := pbReadString(utiText); ok {
				mime = "text/plain"
				text = s
				return nil
			}
			return fmt.Errorf("clipboard is empty or unsupported")
		case "image":
			b, ok := pbReadData(utiPNG)
			if !ok {
				return fmt.Errorf("no image/png in clipboard")
			}
			mime = "image/png"
			data = b
			return nil
		case "html":
			s, ok := pbReadString(utiHTML)
			if !ok {
				return fmt.Errorf("no text/html in clipboard")
			}
			mime = "text/html"
			text = s
			return nil
		case "text":
			s, ok := pbReadString(utiText)
			if !ok {
				return fmt.Errorf("no text/plain in clipboard")
			}
			mime = "text/plain"
			text = s
			return nil
		default:
			return fmt.Errorf("unsupported format: %q", in.Format)
		}
	}); err != nil {
		return nil, err
	}

	out := &ReadClipboardOutput{MimeType: mime}
	if len(data) > 0 {
		out.Encoding = "base64"
		out.Data = base64.StdEncoding.EncodeToString(data)
		return out, nil
	}
	out.Text = text
	return out, nil
}

func (s *Service) WriteClipboard(_ context.Context, in *WriteClipboardInput) (*WriteClipboardOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("missing input")
	}
	mime := strings.ToLower(strings.TrimSpace(in.MimeType))
	if mime == "" {
		mime = "text/plain"
	}

	return &WriteClipboardOutput{}, s.withTimings(in.Timing, func() error {
		switch mime {
		case "text/plain":
			if !pbWriteString(utiText, in.Text) {
				return fmt.Errorf("failed to write text/plain")
			}
			return nil
		case "text/html":
			if !pbWriteString(utiHTML, in.Text) {
				return fmt.Errorf("failed to write text/html")
			}
			return nil
		case "image/png":
			if strings.ToLower(strings.TrimSpace(in.Encoding)) != "base64" {
				return fmt.Errorf("image/png requires encoding=base64")
			}
			b, err := base64.StdEncoding.DecodeString(in.Data)
			if err != nil {
				return err
			}
			if len(b) == 0 {
				return fmt.Errorf("empty image data")
			}
			if !pbWriteData(utiPNG, b) {
				return fmt.Errorf("failed to write image/png")
			}
			return nil
		default:
			return fmt.Errorf("unsupported mimeType: %q", in.MimeType)
		}
	})
}

func pbReadString(uti string) (string, bool) {
	cuti := C.CString(uti)
	defer C.free(unsafe.Pointer(cuti))
	cs := C.pb_read_string(cuti)
	if cs == nil {
		return "", false
	}
	defer C.free(unsafe.Pointer(cs))
	return C.GoString(cs), true
}

func pbReadData(uti string) ([]byte, bool) {
	cuti := C.CString(uti)
	defer C.free(unsafe.Pointer(cuti))
	var ln C.int
	ptr := C.pb_read_data(cuti, &ln)
	if ptr == nil || ln <= 0 {
		return nil, false
	}
	defer C.free(ptr)
	b := C.GoBytes(ptr, ln)
	return b, true
}

func pbWriteString(uti string, text string) bool {
	cuti := C.CString(uti)
	defer C.free(unsafe.Pointer(cuti))
	ct := C.CString(text)
	defer C.free(unsafe.Pointer(ct))
	return C.pb_write_string(cuti, ct) == 1
}

func pbWriteData(uti string, data []byte) bool {
	cuti := C.CString(uti)
	defer C.free(unsafe.Pointer(cuti))
	return C.pb_write_data(cuti, unsafe.Pointer(&data[0]), C.int(len(data))) == 1
}

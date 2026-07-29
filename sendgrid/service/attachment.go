package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	neturl "net/url"
	"path/filepath"
	"strings"

	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"github.com/viant/afs"
	afsscratchpad "github.com/viant/afs/scratchpad"
)

type resolvedAttachment struct {
	name        string
	contentType string
	data        []byte
}

type attachmentResolver struct {
	fs             afs.Service
	scratchpad     *afsscratchpad.Service
	allowedSchemes map[string]bool
	maxDecoded     int64
}

func newAttachmentResolver(cfg Config, fs afs.Service, scratchpad *afsscratchpad.Service, maxDecoded int64) *attachmentResolver {
	allowed := map[string]bool{}
	for _, scheme := range cfg.AttachmentSourceSchemes {
		allowed[scheme] = true
	}
	return &attachmentResolver{
		fs:             fs,
		scratchpad:     scratchpad,
		allowedSchemes: allowed,
		maxDecoded:     maxDecoded,
	}
}

func (r *attachmentResolver) resolve(ctx context.Context, input []EmailAttachment) ([]resolvedAttachment, error) {
	if len(input) > MaxAttachments {
		return nil, validationErrorf("attachments must contain at most %d items", MaxAttachments)
	}
	result := make([]resolvedAttachment, 0, len(input))
	var total int64
	for i, item := range input {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := strings.TrimSpace(item.Name)
		if name == "" {
			return nil, validationErrorf("attachments[%d].name is required", i)
		}
		if strings.ContainsAny(name, "\r\n") {
			return nil, validationErrorf("attachments[%d].name contains an invalid newline", i)
		}
		hasData := strings.TrimSpace(item.DataBase64) != ""
		hasSource := strings.TrimSpace(item.SourceURL) != ""
		if hasData == hasSource {
			return nil, validationErrorf("attachments[%d] must provide exactly one of dataBase64 or sourceURL", i)
		}

		remaining := r.maxDecoded - total
		if remaining <= 0 {
			return nil, validationErrorf("decoded attachments exceed the %d byte limit", r.maxDecoded)
		}
		var data []byte
		var err error
		if hasData {
			data, err = decodeBase64(item.DataBase64, remaining, r.maxDecoded)
		} else {
			data, err = r.readSource(ctx, item.SourceURL, remaining)
		}
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			return nil, validationErrorf("attachments[%d] %s: %v", i, name, err)
		}
		total += int64(len(data))
		result = append(result, resolvedAttachment{
			name:        name,
			contentType: attachmentContentType(item),
			data:        data,
		})
	}
	return result, nil
}

func (r *attachmentResolver) readSource(ctx context.Context, sourceURL string, limit int64) ([]byte, error) {
	sourceURL = strings.TrimSpace(sourceURL)
	scheme := sourceScheme(sourceURL)
	if !r.allowedSchemes[scheme] {
		return nil, fmt.Errorf("sourceURL scheme %q is not allowed", scheme)
	}

	var reader io.ReadCloser
	var err error
	if scheme == afsscratchpad.Scheme {
		artifactID, parseErr := scratchpadArtifactID(sourceURL)
		if parseErr != nil {
			return nil, parseErr
		}
		_, reader, err = r.scratchpad.OpenArtifact(ctx, artifactID)
	} else {
		reader, err = r.fs.OpenURL(ctx, sourceURL)
	}
	if err != nil {
		return nil, fmt.Errorf("read sourceURL: %w", err)
	}
	defer reader.Close()

	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read sourceURL: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("decoded attachments exceed the %d byte limit", r.maxDecoded)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return data, nil
}

func scratchpadArtifactID(sourceURL string) (string, error) {
	parsed, err := neturl.Parse(strings.TrimSpace(sourceURL))
	if err != nil {
		return "", fmt.Errorf("invalid scratchpad sourceURL: %w", err)
	}
	if !strings.EqualFold(parsed.Scheme, afsscratchpad.Scheme) || !strings.EqualFold(parsed.Host, "artifact") {
		return "", fmt.Errorf("scratchpad sourceURL must use scratchpad://artifact/<id>")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("scratchpad sourceURL must not contain query or fragment")
	}
	artifactID := strings.Trim(parsed.Path, "/")
	if artifactID == "" {
		return "", fmt.Errorf("scratchpad artifact id is required")
	}
	return artifactID, nil
}

func sourceScheme(sourceURL string) string {
	parsed, err := neturl.Parse(strings.TrimSpace(sourceURL))
	if err == nil && strings.TrimSpace(parsed.Scheme) != "" {
		return strings.ToLower(strings.TrimSpace(parsed.Scheme))
	}
	return "file"
}

func decodeBase64(value string, remaining, maxDecoded int64) ([]byte, error) {
	maxEncoded := int(^uint(0) >> 1)
	maxEncodableBytes := int64((maxEncoded / 4) * 3)
	if remaining <= maxEncodableBytes {
		maxEncoded = base64.StdEncoding.EncodedLen(int(remaining))
	}
	capacity := len(value)
	if capacity > maxEncoded {
		capacity = maxEncoded
	}
	compact := make([]byte, 0, capacity)
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '\n', '\r', '\t', ' ':
			continue
		}
		if len(compact) == maxEncoded {
			return nil, fmt.Errorf("decoded attachments exceed the %d byte limit", maxDecoded)
		}
		compact = append(compact, value[i])
	}
	data := make([]byte, base64.StdEncoding.DecodedLen(len(compact)))
	n, err := base64.StdEncoding.Decode(data, compact)
	if err != nil {
		return nil, fmt.Errorf("invalid dataBase64")
	}
	data = data[:n]
	if int64(len(data)) > remaining {
		return nil, fmt.Errorf("decoded attachments exceed the %d byte limit", maxDecoded)
	}
	return data, nil
}

func attachmentContentType(input EmailAttachment) string {
	if value := strings.TrimSpace(input.ContentType); value != "" {
		return value
	}
	if ext := filepath.Ext(input.Name); ext != "" {
		if value := mime.TypeByExtension(ext); value != "" {
			return value
		}
	}
	return "application/octet-stream"
}

func sendGridAttachments(input []resolvedAttachment) []*mail.Attachment {
	result := make([]*mail.Attachment, 0, len(input))
	for _, item := range input {
		result = append(result, mail.NewAttachment().
			SetContent(base64.StdEncoding.EncodeToString(item.data)).
			SetType(item.contentType).
			SetFilename(item.name).
			SetDisposition("attachment"))
	}
	return result
}

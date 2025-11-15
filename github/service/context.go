package service

import "context"

type cidKey struct{}

var cidCtxKey = cidKey{}

// WithCID attaches a correlation id to context for debug logging.
func WithCID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, cidCtxKey, id)
}

// CID retrieves a correlation id from context for debug logging.
func CID(ctx context.Context) string {
	v := ctx.Value(cidCtxKey)
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

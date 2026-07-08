package mcp

import (
	"context"
	"log"
	"os"
	"strings"
	"time"
)

func debugEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("OUTLOOK_MCP_DEBUG")))
	return v != "" && v != "0" && v != "false"
}

func debugf(format string, args ...any) {
	if !debugEnabled() {
		return
	}
	log.Printf("[outlook-debug] "+format, args...)
}

func debugDeadline(ctx context.Context) string {
	if ctx == nil {
		return "none"
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return "none"
	}
	return time.Until(deadline).Round(time.Millisecond).String()
}

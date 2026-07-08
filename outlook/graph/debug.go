package graph

import (
	"context"
	"log"
	"time"
)

func debugf(format string, args ...any) {
	if !outlookDebug() {
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

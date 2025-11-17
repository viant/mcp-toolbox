package service

import (
	"fmt"
	neturl "net/url"
	"strings"
)

// ParseSlackMessageURL extracts channel ID and timestamps from a Slack message URL.
// Supports form: https://{workspace}.slack.com/archives/{CHANNEL}/p{tsNoDot}[?thread_ts=...]
// Returns: channelID, message ts (with dot), thread parent ts (with dot; equals ts when thread_ts missing).
func ParseSlackMessageURL(link string) (string, string, string, error) {
	u, err := neturl.Parse(strings.TrimSpace(link))
	if err != nil {
		return "", "", "", err
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 3 || !strings.EqualFold(parts[0], "archives") {
		return "", "", "", fmt.Errorf("unrecognized slack url path: %s", u.Path)
	}
	channel := parts[1]
	msg := parts[2]
	if !strings.HasPrefix(msg, "p") || len(msg) < 8 {
		return "", "", "", fmt.Errorf("missing message anchor in url path")
	}
	digits := msg[1:]
	if len(digits) <= 6 {
		return "", "", "", fmt.Errorf("invalid message timestamp")
	}
	sec := digits[:len(digits)-6]
	frac := digits[len(digits)-6:]
	ts := sec + "." + frac
	thread := ts
	if v := u.Query().Get("thread_ts"); strings.TrimSpace(v) != "" {
		thread = v
	}
	return channel, ts, thread, nil
}

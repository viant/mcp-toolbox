package service

import (
	"strings"
	"time"

	"github.com/viant/scy"
)

const (
	DefaultRegion                    = "global"
	DefaultMaxConcurrentSends        = 4
	DefaultSendTimeout               = 60 * time.Second
	DefaultMaxDecodedAttachmentBytes = int64(21_000_000)
	DefaultMaxPayloadBytes           = int64(29_000_000)
	MaxAttachments                   = 10
	MaxRecipients                    = 1000
)

// Config controls SendGrid delivery and attachment resolution.
type Config struct {
	APIKeyRef               scy.EncodedResource
	CredentialDiagnostics   bool
	Region                  string
	ScratchpadRootURI       string
	AttachmentSourceSchemes []string
	ScratchpadTargetSchemes []string
	MaxConcurrentSends      int
	SendTimeout             time.Duration
}

func (c *Config) normalize() {
	c.APIKeyRef = scy.EncodedResource(strings.TrimSpace(string(c.APIKeyRef)))
	c.Region = strings.ToLower(strings.TrimSpace(c.Region))
	if c.Region == "" {
		c.Region = DefaultRegion
	}
	c.ScratchpadRootURI = strings.TrimSpace(c.ScratchpadRootURI)
	c.AttachmentSourceSchemes = normalizeSchemes(c.AttachmentSourceSchemes)
	c.ScratchpadTargetSchemes = normalizeSchemes(c.ScratchpadTargetSchemes)
	if c.MaxConcurrentSends == 0 {
		c.MaxConcurrentSends = DefaultMaxConcurrentSends
	}
	if c.SendTimeout == 0 {
		c.SendTimeout = DefaultSendTimeout
	}
}

func normalizeSchemes(values []string) []string {
	seen := map[string]bool{}
	var result []string
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

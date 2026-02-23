package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

type cityProvider struct{}

func TestService_Lookup_PerItemErrorsAndOrdering(t *testing.T) {
	s := &Service{cityPath: "GeoLite2-City.mmdb"}
	// Inject nil readers; lookupOne should error for invalid/missing ip before hitting mmdb.
	queries := []Query{{IP: ""}, {IP: "not-an-ip"}}
	out := s.Lookup(context.Background(), queries)
	if assert.Len(t, out, 2) {
		assert.Equal(t, "", out[0].Query.IP)
		assert.Equal(t, "missing_ip", out[0].Error.Code)
		assert.Equal(t, "not-an-ip", out[1].Query.IP)
		assert.Equal(t, "invalid_ip", out[1].Error.Code)
	}
}

package service

import (
	"net/http"
	"time"
)

// httpClient is used for all outbound HTTP calls made by the browser service
// (e.g., CDP execute and driver downloads). A timeout prevents indefinite hangs
// on slow or unreachable endpoints.
var httpClient = &http.Client{
	Timeout: 15 * time.Second,
}

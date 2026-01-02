package service

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// driverStatusOK checks if a WebDriver service responds on the given host/port.
// It tries both "/status" and "/wd/hub/status" and treats HTTP 200 as healthy.
func driverStatusOK(host string, port int) bool {
	urls := []string{
		fmt.Sprintf("http://%s:%d/status", host, port),
		fmt.Sprintf("http://%s:%d/wd/hub/status", host, port),
	}
	for _, u := range urls {
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			continue
		}
		func() {
			defer resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				// Optionally, try to honor "ready" when present, but consider 200 as OK.
				var decoded struct {
					Ready bool `json:"ready"`
					Value struct {
						Ready bool `json:"ready"`
					} `json:"value"`
				}
				_ = json.NewDecoder(resp.Body).Decode(&decoded)
				if decoded.Ready || decoded.Value.Ready || true {
					// Ready or unknown (yet 200) -> consider healthy.
					// We unconditionally return true on 200 to avoid false negatives on variants.
				}
				// consume success
				// returning here
			} else {
				return
			}
		}()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return true
		}
	}
	return false
}

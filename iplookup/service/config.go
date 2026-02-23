package service

import (
	"fmt"
	"os"
)

// Config represents iplookup configuration.
//
// City is required, ISP is optional.
// Both GeoIP2 (paid) and GeoLite2 (free) are supported by providing the file paths.
type Config struct {
	CityMMDBPath string
	ISPMMDBPath  string
}

func (c *Config) Validate() error {
	if c.CityMMDBPath == "" {
		return fmt.Errorf("CityMMDBPath is required")
	}
	return nil
}

func LoadConfigFromEnv() (*Config, error) {
	cfg := &Config{
		CityMMDBPath: os.Getenv("IPLOOKUP_CITY_MMDB_PATH"),
		ISPMMDBPath:  os.Getenv("IPLOOKUP_ISP_MMDB_PATH"),
	}
	return cfg, cfg.Validate()
}

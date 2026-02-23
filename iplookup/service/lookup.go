package service

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/oschwald/geoip2-golang"
)

type Service struct {
	city *geoip2.Reader
	isp  *geoip2.Reader

	cityPath string
	ispPath  string
}

func New(cfg *Config) (*Service, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config was nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	city, err := geoip2.Open(cfg.CityMMDBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open City mmdb %q: %w", cfg.CityMMDBPath, err)
	}

	var isp *geoip2.Reader
	if cfg.ISPMMDBPath != "" {
		isp, err = geoip2.Open(cfg.ISPMMDBPath)
		if err != nil {
			_ = city.Close()
			return nil, fmt.Errorf("failed to open ISP mmdb %q: %w", cfg.ISPMMDBPath, err)
		}
	}

	return &Service{city: city, isp: isp, cityPath: cfg.CityMMDBPath, ispPath: cfg.ISPMMDBPath}, nil
}

func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	if s.isp != nil {
		_ = s.isp.Close()
	}
	if s.city != nil {
		return s.city.Close()
	}
	return nil
}

func (s *Service) Lookup(ctx context.Context, queries []Query) []Result {
	_ = ctx
	results := make([]Result, len(queries))
	for i, q := range queries {
		results[i] = s.lookupOne(q)
	}
	return results
}

func (s *Service) lookupOne(q Query) Result {
	res := Result{
		Query: q,
		Meta: Meta{
			Provider: "maxmind",
			Dataset: DatasetMeta{
				City: filepath.Base(s.cityPath),
				ISP:  filepath.Base(s.ispPath),
			},
			Cached: false,
		},
	}

	ipStr := strings.TrimSpace(q.IP)
	if ipStr == "" {
		res.Error = &Error{Code: "missing_ip", Message: "ip is required"}
		return res
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		res.Error = &Error{Code: "invalid_ip", Message: "unable to parse ip"}
		return res
	}
	if s.city == nil {
		res.Error = &Error{Code: "not_configured", Message: "city mmdb reader not configured"}
		return res
	}

	cityRec, err := s.city.City(ip)
	if err != nil {
		res.Error = &Error{Code: "lookup_failed", Message: err.Error()}
		return res
	}

	geo := &Geo{}
	if cityRec.Country.IsoCode != "" {
		geo.CountryCode = strings.ToUpper(cityRec.Country.IsoCode)
	}
	if len(cityRec.Subdivisions) > 0 {
		geo.RegionCode = cityRec.Subdivisions[0].IsoCode
		geo.State = cityRec.Subdivisions[0].IsoCode
	}
	geo.City = cityRec.City.Names["en"]
	geo.Zip = cityRec.Postal.Code
	geo.Lat = cityRec.Location.Latitude
	geo.Lon = cityRec.Location.Longitude
	geo.TimeZone = cityRec.Location.TimeZone
	geo.MetroCode = int(cityRec.Location.MetroCode)
	geo.DMA = geo.MetroCode
	res.Geo = geo

	if s.isp != nil {
		ispRec, err := s.isp.ISP(ip)
		if err == nil {
			out := &ISP{}
			out.ISP = ispRec.ISP
			out.Organization = ispRec.Organization
			if out.ISP != "" || out.Organization != "" {
				res.ISP = out
			}
		}
	}

	return res
}

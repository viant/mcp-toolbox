package service

type Query struct {
	IP string `json:"ip" yaml:"ip"`
}

type Error struct {
	Code    string `json:"code" yaml:"code"`
	Message string `json:"message" yaml:"message"`
}

type Geo struct {
	CountryCode string  `json:"countryCode" yaml:"countryCode"`
	RegionCode  string  `json:"regionCode" yaml:"regionCode"`
	State       string  `json:"state" yaml:"state"`
	City        string  `json:"city" yaml:"city"`
	Zip         string  `json:"zip" yaml:"zip"`
	Lat         float64 `json:"lat" yaml:"lat"`
	Lon         float64 `json:"lon" yaml:"lon"`
	TimeZone    string  `json:"timeZone" yaml:"timeZone"`
	MetroCode   int     `json:"metroCode" yaml:"metroCode"`
	DMA         int     `json:"dma" yaml:"dma"`
}

type ISP struct {
	ISP          string `json:"isp" yaml:"isp"`
	Organization string `json:"organization" yaml:"organization"`
}

type ASN struct {
	ASN          int    `json:"asn" yaml:"asn"`
	Organization string `json:"organization" yaml:"organization"`
	Network      string `json:"network" yaml:"network"`
}

type DatasetMeta struct {
	City string `json:"city" yaml:"city"`
	ISP  string `json:"isp" yaml:"isp"`
	ASN  string `json:"asn" yaml:"asn"`
}

type Meta struct {
	Provider string      `json:"provider" yaml:"provider"`
	Dataset  DatasetMeta `json:"dataset" yaml:"dataset"`
	Cached   bool        `json:"cached" yaml:"cached"`
}

type Result struct {
	Query Query  `json:"query" yaml:"query"`
	Geo   *Geo   `json:"geo" yaml:"geo"`
	ISP   *ISP   `json:"isp" yaml:"isp"`
	ASN   *ASN   `json:"asn" yaml:"asn"`
	Meta  Meta   `json:"meta" yaml:"meta"`
	Error *Error `json:"error" yaml:"error"`
}

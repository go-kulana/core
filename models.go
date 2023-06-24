package core

import (
	"github.com/boatware/domainer"
	"time"
)

type Settings struct {
	FallbackPort     int    `json:"default_port,omitempty"`
	FallbackProtocol string `json:"default_protocol,omitempty"`
	RedirectLimit    int    `json:"redirect_limit,omitempty"`
	UserAgent        string `json:"default_user_agent,omitempty"`
}

var RequestSettings = Settings{
	FallbackPort:     443,
	FallbackProtocol: "https",
	RedirectLimit:    10,
	UserAgent:        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36",
}

type TlsCertificate struct {
	Subject string `json:"subject,omitempty"`
	Issuer  string `json:"issuer,omitempty"`
	Expires string `json:"expires,omitempty"`
	IsValid bool   `json:"is_valid,omitempty"`
}

type DNS struct {
	MX    []string `json:"mx,omitempty"`
	TXT   []string `json:"txt,omitempty"`
	A     []string `json:"a,omitempty"`
	CNAME []string `json:"cname,omitempty"`
	NS    []string `json:"ns,omitempty"`
	SRV   []string `json:"srv,omitempty"`
}

type HostInfo struct {
	RequestTimestamp time.Time       `json:"request_timestamp,omitempty"`
	URL              *domainer.URL   `json:"url,omitempty"`
	HttpStatusCode   int             `json:"http_status_code,omitempty"`
	RedirectUrls     []string        `json:"redirect_urls,omitempty"`
	RedirectCount    int             `json:"redirect_count,omitempty"`
	TlsCertificate   *TlsCertificate `json:"tls_certificate,omitempty"`
	PingTime         float64         `json:"ping_time,omitempty"`
	HttpResponseTime float64         `json:"http_response_time,omitempty"`
	DNS              *DNS            `json:"dns,omitempty"`
	Errors           []string        `json:"errors,omitempty"`
}

package core

import (
	"crypto/tls"
	"github.com/boatware/domainer"
	"net/http"
	"time"
)

const Debug = true

func nanoTime() int64 {
	return time.Now().UnixNano()
}

func nanoToMilli(nano int64) float64 {
	return float64(nano) / 1000000
}

func createHttpClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: tr,
	}
}

func buildInfo(domain string) (*HostInfo, error) {
	url, err := domainer.FromString(domain)
	if err != nil {
		if Debug {
			panic(err)
		}
		return &HostInfo{}, err
	}

	info := &HostInfo{}

	if url.Port == 0 {
		url.Port = RequestSettings.FallbackPort
	}

	if url.Protocol == "" {
		url.Protocol = RequestSettings.FallbackProtocol
	}

	info.URL = url

	// Add the current time in UTC
	info.RequestTimestamp = time.Now().UTC()

	return info, nil
}

func getHostname(domain string) (string, error) {
	url, err := domainer.FromString(domain)
	if err != nil {
		if Debug {
			panic(err)
		}
		return "", err
	}

	return url.Hostname, nil
}

package core

import (
	"fmt"
	"github.com/boatware/domainer"
)

func GetRawResponseTime(domain string) (int, float64, error) {
	redirectCount = 0
	redirectUrls = []string{}
	url, err := domainer.FromString(domain)
	if err != nil {
		if Debug {
			panic(err)
		}
		return 0, 0, err
	}

	if url.Protocol == "" {
		url.Protocol = RequestSettings.FallbackProtocol
		url.FullURL = url.Protocol + "://" + url.FullURL
	}

	// Fetch the host
	fullUrl := fmt.Sprintf("%s://%s.%s", url.Protocol, url.Domain, url.TLD)
	if url.Subdomain != "" {
		fullUrl = fmt.Sprintf("%s://%s.%s.%s", url.Protocol, url.Subdomain, url.Domain, url.TLD)
	}

	return fetch(fullUrl, url)
}

func GetRawPing(domain string) (int64, error) {
	url, err := domainer.FromString(domain)
	if err != nil {
		if Debug {
			panic(err)
		}
		return 0, err
	}

	return ping(url)
}

func GetRawMX(domain string) []string {
	url, err := domainer.FromString(domain)
	if err != nil {
		if Debug {
			panic(err)
		}
		return []string{}
	}

	domain = fmt.Sprintf("%s.%s", url.Domain, url.TLD)
	if url.Subdomain != "" {
		domain = fmt.Sprintf("%s.%s.%s", url.Subdomain, url.Domain, url.TLD)
	}

	return fetchMXRecords(domain)
}

func GetRawTXT(domain string) []string {
	hostname, err := getHostname(domain)
	if err != nil {
		if Debug {
			panic(err)
		}
		return []string{}
	}

	return fetchTXTRecords(hostname)
}

func GetRawA(domain string) []string {
	hostname, err := getHostname(domain)
	if err != nil {
		if Debug {
			panic(err)
		}
		return []string{}
	}

	return fetchARecords(hostname)
}

func GetRawCNAME(domain string) []string {
	hostname, err := getHostname(domain)
	if err != nil {
		if Debug {
			panic(err)
		}
		return []string{}
	}

	return fetchCNAMERecords(hostname)
}

func GetRawNS(domain string) []string {
	hostname, err := getHostname(domain)
	if err != nil {
		if Debug {
			panic(err)
		}
		return []string{}
	}

	return fetchNSRecords(hostname)
}

func GetRawSRV(domain string) []string {
	hostname, err := getHostname(domain)
	if err != nil {
		if Debug {
			panic(err)
		}
		return []string{}
	}

	return fetchSRVRecords(hostname)
}

func GetRawTLSCertificate(domain string) (*TlsCertificate, error) {
	url, err := domainer.FromString(domain)
	if err != nil {
		if Debug {
			panic(err)
		}
		return nil, err
	}

	return checkCertificate(url), nil
}

package core

import (
	"crypto/tls"
	"fmt"
	"github.com/boatware/domainer"
	"net"
	"net/http"
	"time"
)

var redirectCount = 0
var redirectUrls []string

func ping(url *domainer.URL) (int64, error) {
	protocol := "tcp"
	timeout := 30
	port := url.Port
	if port == 0 {
		port = RequestSettings.FallbackPort
	}

	address := fmt.Sprintf("%s.%s:%d", url.Domain, url.TLD, port)
	duration := time.Duration(timeout) * time.Second

	start := nanoTime()
	conn, err := net.DialTimeout(protocol, address, duration)
	if err != nil {
		if Debug {
			panic(err)
		}
		return 0, err
	}
	end := nanoTime()
	err = conn.Close()
	if err != nil {
		if Debug {
			panic(err)
		}
		return 0, err
	}

	return end - start, nil
}

func fetch(url string, u *domainer.URL) (int, float64, error) {
	client := createHttpClient()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		if Debug {
			panic(err)
		}
		return 0, 0, err
	}
	req.Header.Set("User-Agent", RequestSettings.UserAgent)

	if u.Username != "" && u.Password != "" {
		req.SetBasicAuth(u.Username, u.Password)
	}

	start := nanoTime()
	resp, err := client.Do(req)
	if err != nil {
		if Debug {
			panic(err)
		}
		return 0, 0, err
	}

	end := nanoTime()
	defer client.CloseIdleConnections()

	statusCode := resp.StatusCode
	responseTime := nanoToMilli(end - start)

	if statusCode >= 300 && statusCode < 400 {
		redirectCount++
		if redirectCount < RequestSettings.RedirectLimit {
			redirectUrl := resp.Header.Get("Location")
			redirectUrls = append(redirectUrls, redirectUrl)
			return fetch(redirectUrl, u)
		}
	}

	return statusCode, responseTime, nil
}

func checkCertificate(url *domainer.URL) *TlsCertificate {
	cert := &TlsCertificate{}
	hostname := fmt.Sprintf("%s.%s", url.Domain, url.TLD)
	conn, err := tls.Dial("tcp", hostname+":443", nil)
	if err != nil {
		if Debug {
			panic(err)
		}
		// Server doesn't support TLS
		return cert
	}

	err = conn.VerifyHostname(hostname)
	if err != nil {
		if Debug {
			panic(err)
		}
		return cert
	}

	expiry := conn.ConnectionState().PeerCertificates[0].NotAfter
	issuer := conn.ConnectionState().PeerCertificates[0].Issuer
	issuerString := fmt.Sprintf("%v", issuer)

	cert.Subject = hostname
	cert.Issuer = issuerString
	cert.Expires = expiry.Format("2006-01-02 15:04:05")
	cert.IsValid = conn.ConnectionState().PeerCertificates[0].NotAfter.After(time.Now())

	return cert
}

func fetchMXRecords(domain string) []string {
	records, err := net.LookupMX(domain)
	if err != nil {
		return nil
	}

	var mxRecords []string
	for _, record := range records {
		mxRecords = append(mxRecords, record.Host)
	}

	return mxRecords
}

func fetchTXTRecords(domain string) []string {
	records, err := net.LookupTXT(domain)
	if err != nil {
		return nil
	}

	return records
}

func fetchARecords(domain string) []string {
	records, err := net.LookupHost(domain)
	if err != nil {
		return nil
	}

	return records
}

func fetchNSRecords(domain string) []string {
	records, err := net.LookupNS(domain)
	if err != nil {
		return nil
	}

	var nsRecords []string
	for _, record := range records {
		nsRecords = append(nsRecords, record.Host)
	}

	return nsRecords
}

func fetchSRVRecords(domain string) []string {
	_, records, err := net.LookupSRV("", "", domain)
	if err != nil {
		return nil
	}

	var srvRecords []string
	for _, record := range records {
		srvRecords = append(srvRecords, fmt.Sprintf("%s:%d", record.Target, record.Port))
	}

	return srvRecords
}

func fetchCNAMERecords(domain string) []string {
	records, err := net.LookupCNAME(domain)
	if err != nil {
		return nil
	}

	return []string{records}
}

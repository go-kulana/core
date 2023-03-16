package main

import (
	"crypto/tls"
	"fmt"
	"github.com/boatware/domainer"
	"net"
	"net/http"
	"time"
)

func ping(url *domainer.URL) (int64, error) {
	protocol := "tcp"
	timeout := 30
	port := url.Port

	address := fmt.Sprintf("%s.%s:%d", url.Domain, url.TLD, port)
	duration := time.Duration(timeout) * time.Second

	start := nanoTime()
	conn, err := net.DialTimeout(protocol, address, duration)
	if err != nil {
		return 0, err
	}
	end := nanoTime()
	err = conn.Close()
	if err != nil {
		return 0, err
	}

	return end - start, nil
}

func fetch(info *HostInfo, url string) error {
	client := createHttpClient()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", RequestSettings.UserAgent)

	if info.URL.Username != "" && info.URL.Password != "" {
		req.SetBasicAuth(info.URL.Username, info.URL.Password)
	}

	start := nanoTime()
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	end := nanoTime()
	defer client.CloseIdleConnections()

	info.HttpStatusCode = resp.StatusCode
	info.HttpResponseTime = nanoToMilli(end - start)

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if info.RedirectCount < RequestSettings.RedirectLimit {
			info.RedirectCount++
			redirectUrl := resp.Header.Get("Location")
			info.RedirectUrls = append(info.RedirectUrls, redirectUrl)
			return fetch(info, redirectUrl)
		}
	}

	return nil
}

func checkCertificate(url *domainer.URL) *TlsCertificate {
	cert := &TlsCertificate{}
	hostname := fmt.Sprintf("%s.%s", url.Domain, url.TLD)
	conn, err := tls.Dial("tcp", hostname+":443", nil)
	if err != nil {
		// Server doesn't support TLS
		return cert
	}

	err = conn.VerifyHostname(hostname)
	if err != nil {
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

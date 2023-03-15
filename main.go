package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/boatware/domainer"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

const defaultPort = 443
const defaultProtocol = "https"
const redirectLimit = 10

type TlsCertificate struct {
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
	Expires string `json:"expires"`
	IsValid bool   `json:"is_valid"`
}

type DNS struct {
	MX    []string `json:"mx"`
	TXT   []string `json:"txt"`
	A     []string `json:"a"`
	CNAME []string `json:"cname"`
	NS    []string `json:"ns"`
	SRV   []string `json:"srv"`
}

type HostInfo struct {
	URL              *domainer.URL   `json:"url"`
	HttpStatusCode   int             `json:"http_status_code"`
	RedirectUrls     []string        `json:"redirect_urls"`
	RedirectCount    int             `json:"redirect_count"`
	TlsCertificate   *TlsCertificate `json:"tls_certificate"`
	PingTime         float64         `json:"ping_time"`
	HttpResponseTime float64         `json:"http_response_time"`
	DNS              *DNS            `json:"dns"`
}

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
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36")

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
		if info.RedirectCount < redirectLimit {
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

func CollectData(domain string) (*HostInfo, error) {
	info := &HostInfo{}

	// go run . check -d http://user:pass@ohano.me:port/path/to/file.extension?query=string#fragment
	url, err := domainer.FromString(domain)
	if err != nil {
		return info, err
	}

	if url.Port == 0 {
		url.Port = defaultPort
	}

	if url.Protocol == "" {
		url.Protocol = defaultProtocol
	}

	info.URL = url

	// Ping the host by sending a HEAD request
	pingTime, err := ping(url)
	if err != nil {
		return info, err
	}
	info.PingTime = nanoToMilli(pingTime)

	// Fetch the host
	fullUrl := fmt.Sprintf("%s://%s.%s", url.Protocol, url.Domain, url.TLD)
	if url.Subdomain != "" {
		fullUrl = fmt.Sprintf("%s://%s.%s.%s", url.Protocol, url.Subdomain, url.Domain, url.TLD)
	}
	err = fetch(info, fullUrl)
	if err != nil {
		fmt.Println("err")
		return info, err
	}

	// Check the certificate
	cert := checkCertificate(url)
	info.TlsCertificate = cert

	host := fmt.Sprintf("%s.%s", url.Domain, url.TLD)
	if url.Subdomain != "" {
		host = fmt.Sprintf("%s.%s", url.Subdomain, host)
	}

	dns := &DNS{}
	dns.MX = fetchMXRecords(host)
	dns.TXT = fetchTXTRecords(host)
	dns.A = fetchARecords(host)
	dns.NS = fetchNSRecords(host)
	dns.SRV = fetchSRVRecords(host)
	dns.CNAME = fetchCNAMERecords(host)
	info.DNS = dns

	return info, nil
}

func main() {
	url := "https://ohano.me"
	url = "smtp.ohano.me"

	info, err := CollectData(url)
	if err != nil {
		panic(err)
	}

	marshalled, _ := json.MarshalIndent(info, "", "  ")

	// Check if file exists
	// If it does, delete it
	exists, err := os.Stat("data.json")
	if err == nil {
		if exists != nil {
			err = os.Remove("data.json")
			if err != nil {
				panic(err)
			}
		}
	}

	// Create file
	file, err := os.OpenFile("data.json", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}

	if _, err = file.WriteString(string(marshalled)); err != nil {
		log.Fatal(err)
	}

	err = file.Close()
	if err != nil {
		log.Fatal(err)
	}
}

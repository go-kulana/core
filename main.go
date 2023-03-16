package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

var info = &HostInfo{}

func GetResponseTime(domain string) (*HostInfo, error) {
	if info.URL == nil || info.URL.FullURL != domain {
		info, err := buildInfo(domain)
		if err != nil {
			return info, err
		}
	}

	// Fetch the host
	fullUrl := fmt.Sprintf("%s://%s.%s", info.URL.Protocol, info.URL.Domain, info.URL.TLD)
	if info.URL.Subdomain != "" {
		fullUrl = fmt.Sprintf("%s://%s.%s.%s", info.URL.Protocol, info.URL.Subdomain, info.URL.Domain, info.URL.TLD)
	}
	err := fetch(info, fullUrl)
	if err != nil {
		fmt.Println("err")
		return info, err
	}

	return info, nil
}

func GetPing(domain string) (*HostInfo, error) {
	if info.URL == nil || info.URL.FullURL != domain {
		info, err := buildInfo(domain)
		if err != nil {
			return info, err
		}
	}

	// Ping the host by sending a HEAD request
	pingTime, err := ping(info.URL)
	if err != nil {
		return info, err
	}
	info.PingTime = nanoToMilli(pingTime)

	return info, nil
}

func CollectAllData(domain string) (*HostInfo, error) {
	if info.URL == nil {
		info, err := buildInfo(domain)
		if err != nil {
			return info, err
		}
	}

	// Ping the host by sending a HEAD request
	pingTime, err := ping(info.URL)
	if err != nil {
		return info, err
	}
	info.PingTime = nanoToMilli(pingTime)

	// Fetch the host
	fullUrl := fmt.Sprintf("%s://%s.%s", info.URL.Protocol, info.URL.Domain, info.URL.TLD)
	if info.URL.Subdomain != "" {
		fullUrl = fmt.Sprintf("%s://%s.%s.%s", info.URL.Protocol, info.URL.Subdomain, info.URL.Domain, info.URL.TLD)
	}
	err = fetch(info, fullUrl)
	if err != nil {
		fmt.Println("err")
		return info, err
	}

	// Check the certificate
	cert := checkCertificate(info.URL)
	info.TlsCertificate = cert

	host := fmt.Sprintf("%s.%s", info.URL.Domain, info.URL.TLD)
	if info.URL.Subdomain != "" {
		host = fmt.Sprintf("%s.%s", info.URL.Subdomain, host)
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

func saveToFile(hostInfo *HostInfo, filename string) {
	marshalled, _ := json.MarshalIndent(info, "", "  ")

	// Check if file exists
	// If it does, delete it
	exists, err := os.Stat(filename + ".json")
	if err == nil {
		if exists != nil {
			err = os.Remove(filename + ".json")
			if err != nil {
				panic(err)
			}
		}
	}

	// Create file
	file, err := os.OpenFile(filename+".json", os.O_CREATE|os.O_WRONLY, 0644)
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

func main() {
	url := "https://kulana.cloud"

	info, err := GetResponseTime(url)
	if err != nil {
		panic(err)
	}
	saveToFile(info, "sample_data_response_time")

	info = &HostInfo{}
	info, err = GetPing(url)
	if err != nil {
		panic(err)
	}
	saveToFile(info, "sample_data_ping")
}

package core

func GetResponseTime(domain string) (*HostInfo, error) {
	redirectCount = 0
	redirectUrls = []string{}
	info, err := buildInfo(domain)
	if err != nil {
		if Debug {
			panic(err)
		}
		return info, err
	}

	statusCode, responseTime, err := GetRawResponseTime(domain)
	if err != nil {
		if Debug {
			panic(err)
		}
		return info, err
	}

	info.HttpStatusCode = statusCode
	info.HttpResponseTime = responseTime
	info.RedirectCount = redirectCount
	info.RedirectUrls = redirectUrls

	if err != nil {
		if Debug {
			panic(err)
		}
		return info, err
	}

	return info, nil
}

func GetPing(domain string) (*HostInfo, error) {
	info, err := buildInfo(domain)
	if err != nil {
		if Debug {
			panic(err)
		}
		return info, err
	}

	// Ping the host by sending a HEAD request
	pingTime, err := GetRawPing(domain)
	if err != nil {
		if Debug {
			panic(err)
		}
		return info, err
	}
	info.PingTime = nanoToMilli(pingTime)

	return info, nil
}

func GetMX(domain string) (*HostInfo, error) {
	info, err := buildInfo(domain)
	if err != nil {
		if Debug {
			panic(err)
		}
		return info, err
	}

	info.DNS = &DNS{
		MX: GetRawMX(domain),
	}

	return info, nil
}

func GetTXT(domain string) (*HostInfo, error) {
	info, err := buildInfo(domain)
	if err != nil {
		if Debug {
			panic(err)
		}
		return info, err
	}

	info.DNS = &DNS{
		TXT: GetRawTXT(domain),
	}

	return info, nil
}

func GetA(domain string) (*HostInfo, error) {
	info, err := buildInfo(domain)
	if err != nil {
		if Debug {
			panic(err)
		}
		return info, err
	}

	info.DNS = &DNS{
		A: GetRawA(domain),
	}

	return info, nil
}

func GetCNAME(domain string) (*HostInfo, error) {
	info, err := buildInfo(domain)
	if err != nil {
		if Debug {
			panic(err)
		}
		return info, err
	}

	info.DNS = &DNS{
		CNAME: GetRawCNAME(domain),
	}

	return info, nil
}

func GetNS(domain string) (*HostInfo, error) {
	info, err := buildInfo(domain)
	if err != nil {
		if Debug {
			panic(err)
		}
		return info, err
	}

	info.DNS = &DNS{
		NS: GetRawNS(domain),
	}

	return info, nil
}

func GetSRV(domain string) (*HostInfo, error) {
	info, err := buildInfo(domain)
	if err != nil {
		if Debug {
			panic(err)
		}
		return info, err
	}

	info.DNS = &DNS{
		SRV: GetRawSRV(domain),
	}

	return info, nil
}

func GetDNS(domain string) (*HostInfo, error) {
	info, err := buildInfo(domain)
	if err != nil {
		if Debug {
			panic(err)
		}
		return info, err
	}

	info.DNS = &DNS{
		MX:    GetRawMX(domain),
		TXT:   GetRawTXT(domain),
		A:     GetRawA(domain),
		CNAME: GetRawCNAME(domain),
		NS:    GetRawNS(domain),
		SRV:   GetRawSRV(domain),
	}

	return info, nil
}

func GetTLSCertificate(domain string) (*HostInfo, error) {
	info, err := buildInfo(domain)
	if err != nil {
		if Debug {
			panic(err)
		}
		return info, err
	}

	info.TlsCertificate, err = GetRawTLSCertificate(domain)
	if err != nil {
		if Debug {
			panic(err)
		}
		return info, err
	}

	return info, nil
}

func GetAll(domain string) (*HostInfo, error) {
	info, err := buildInfo(domain)
	if err != nil {
		if Debug {
			panic(err)
		}

		// Return at this point because it doesn't make sense to continue.
		return info, err
	}

	statusCode, responseTime, err := GetRawResponseTime(domain)
	if err != nil {
		if Debug {
			panic(err)
		}

		// Append error to the list of errors
		info.Errors = append(info.Errors, err.Error())
	}

	// It only makes sense to get the following information if the response time was successful
	if err == nil {
		info.HttpStatusCode = statusCode
		info.HttpResponseTime = responseTime
		info.RedirectCount = redirectCount
		info.RedirectUrls = redirectUrls
	}

	pingTime, err := GetRawPing(domain)
	if err != nil {
		if Debug {
			panic(err)
		}

		// Append error to the list of errors
		info.Errors = append(info.Errors, err.Error())
	}

	if err == nil {
		info.PingTime = nanoToMilli(pingTime)
	}

	// The DNS infos don't need to be error-handled like above because the functions simply return empty arrays if there is an error.
	info.DNS = &DNS{
		MX:    GetRawMX(domain),
		TXT:   GetRawTXT(domain),
		A:     GetRawA(domain),
		CNAME: GetRawCNAME(domain),
		NS:    GetRawNS(domain),
		SRV:   GetRawSRV(domain),
	}

	tlsCertificate, err := GetRawTLSCertificate(domain)
	if err != nil {
		if Debug {
			panic(err)
		}

		// Append error to the list of errors
		info.Errors = append(info.Errors, err.Error())
	}

	if err == nil {
		info.TlsCertificate = tlsCertificate
	}

	return info, nil
}

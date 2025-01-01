package dns

import (
	"net"
	"regexp"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/retryabledns"
)

func GetARecords(domain string) ([]net.IP, []net.IP) {
	var cfIPs []net.IP
	var nonCFIPs []net.IP

	ips, _ := net.LookupIP(domain)
	if len(ips) > 0 {
		for _, ip := range ips {
			if ip.To4() != nil {
				result, _ := IsInCloudflareIPRange(ip)
				if result {
					cfIPs = append(cfIPs, ip)
				} else {
					nonCFIPs = append(nonCFIPs, ip)
				}
			}
		}
	}
	return cfIPs, nonCFIPs
}

func GetTXTRecords(domain string) ([]string, error) {
	resolvers := []string{"1.1.1.1:53", "8.8.8.8:53", "8.8.4.4:53", "1.0.0.1:53"}
	retries := 3
	dnsClient, err := retryabledns.New(resolvers, retries)
	if err != nil {
		return nil, err
	}

	TXTRecords, err := dnsClient.Query(domain, dns.TypeTXT)
	if err != nil {
		return nil, err
	}

	return TXTRecords.TXT, nil
}

func ExtractIPAddresses(input string) []string {
	ipPattern := `\b(?:\d{1,3}\.){3}\d{1,3}\b`
	re := regexp.MustCompile(ipPattern)
	return re.FindAllString(input, -1)
}

func IsInCloudflareIPRange(aIP net.IP) (bool, net.IP) {
	cloudflareRanges := []string{
		"173.245.48.0/20",
		"103.21.244.0/22",
		"103.22.200.0/22",
		"103.31.4.0/22",
		"141.101.64.0/18",
		"108.162.192.0/18",
		"190.93.240.0/20",
		"188.114.96.0/20",
		"197.234.240.0/22",
		"198.41.128.0/17",
		"162.158.0.0/15",
		"104.16.0.0/13",
		"104.24.0.0/14",
		"172.64.0.0/13",
		"131.0.72.0/22",
	}

	for _, rangeStr := range cloudflareRanges {
		_, cidr, _ := net.ParseCIDR(rangeStr)
		if cidr.Contains(aIP) {
			return true, aIP
		}
	}

	return false, aIP
}

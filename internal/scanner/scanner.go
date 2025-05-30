package scanner

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/gammazero/workerpool"
	"github.com/musana/cf-hero/internal/config"
	"github.com/musana/cf-hero/internal/dns"
	httpClient "github.com/musana/cf-hero/internal/http"
	"github.com/musana/cf-hero/pkg/models"
	"github.com/schollz/progressbar/v3"
)

type Scanner struct {
	Options *models.Options
	URLs    []string
	Domains []string
	Bar     *progressbar.ProgressBar
	mu      sync.Mutex
	Stats   struct {
		Total           int
		Behind          int
		NotBehind       int
		TotalIPsScanned int
		RealIPsFound    int
	}
}

func New(options *models.Options, urls []string, domains []string) *Scanner {
	// Filter valid URLs
	var validURLs []string
	for _, url := range urls {
		if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
			validURLs = append(validURLs, url)
		} else {
			color.Red("[!] %s does not start with http or https. Skipping...", url)
		}
	}

	return &Scanner{
		Options: options,
		URLs:    validURLs,
		Domains: domains,
	}
}

func (s *Scanner) PreScan() {
	color.White("\n[*] Pre-scanning domains to identify Cloudflare protected ones...")
	processed := 0

	wp := workerpool.New(s.Options.Worker)
	var wg sync.WaitGroup

	for _, url := range s.URLs {
		url := url // capture variable
		wg.Add(1)
		wp.Submit(func() {
			defer wg.Done()
			domain := strings.Split(url, "//")[1]
			cfIPs, _ := dns.GetARecords(domain)

			s.mu.Lock()
			processed++
			s.Stats.Total++
			if len(cfIPs) > 0 {
				s.Stats.Behind++
			} else {
				s.Stats.NotBehind++
			}
			s.mu.Unlock()
		})
	}

	wg.Wait()
	wp.StopWait()

	color.White("[+] Found %d/%d domains behind Cloudflare", s.Stats.Behind, s.Stats.Total)

	// Show provided HTML title if exists
	if s.Options.Title != "" {
		color.Cyan("[*] Using provided HTML title: %s", s.Options.Title)
	}

	// Check API keys status at the beginning of the scan
	color.Cyan("\n[*] Checking API keys...")

	// Censys API key check
	if keys := config.ReadAPIKeys("censys"); len(keys) > 0 && keys[0] != "" {
		color.Green("[*] Censys API found in the config file")
	} else {
		color.Yellow("[!] Censys API could not find in the config file")
		s.Options.Censys = false
	}

	// SecurityTrails API key check
	if keys := config.ReadAPIKeys("securitytrails"); len(keys) > 0 && keys[0] != "" {
		color.Green("[*] SecurityTrails API found in the config file")
	} else {
		color.Yellow("[!] SecurityTrails API could not find in the config file")
		s.Options.SecurityTrails = false
	}

	// Shodan API key check
	if keys := config.ReadAPIKeys("shodan"); len(keys) > 0 && keys[0] != "" {
		color.Green("[*] Shodan API found in the config file")
	} else {
		color.Yellow("[!] Shodan API could not find in the config file")
		s.Options.Shodan = false
	}

	// Zoomeye API key check
	if keys := config.ReadAPIKeys("zoomeye"); len(keys) > 0 && keys[0] != "" {
		color.Green("[*] ZoomEye API found in the config file")
	} else {
		color.Yellow("[!] ZoomEye API could not find in the config file")
		s.Options.Zoomeye = false
	}
	color.Cyan("\n[*] Scan has been started for targets...")

	if s.Stats.Behind > 0 {
		s.Bar = progressbar.NewOptions(s.Stats.Behind,
			progressbar.OptionEnableColorCodes(true),
			progressbar.OptionShowCount(),
			progressbar.OptionSetWidth(40),
			progressbar.OptionSetDescription("[cyan][*][reset] Scanning Cloudflare protected domains..."),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "[green]=[reset]",
				SaucerHead:    "[green]>[reset]",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}))
	}
}

func (s *Scanner) Start(url string) {
	if s.Options.CF || s.Options.NCF {
		s.printDomains(url)
		return
	}

	// Check if URL starts with http or https
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		color.Red("[!] %s does not start with http or https. Skipping...", url)
		return
	}

	domain := strings.Split(url, "//")[1]
	cfIPs, nonCFIPs := dns.GetARecords(domain)

	if len(cfIPs) > 0 {

		var actualHTMLTitle string
		if s.Options.Title != "" {
			actualHTMLTitle = s.Options.Title
		} else {
			actualHTMLTitle, _ = s.getHTMLTitle(url)
		}

		color.White("[*] Target Information: [ %s (%s) (Cloudflare) - Title: %s ]", domain, cfIPs[0], actualHTMLTitle)

		// Check API keys status only once at the beginning
		/*
			if url == s.URLs[0] {

				// Censys API key check
				if s.Options.Censys {
					if keys := config.ReadAPIKeys("censys"); len(keys) > 0 && keys[0] != "" {
						color.Green("[*] Censys API found in the config file")
					} else {
						color.Yellow("[!] Censys API could not find in the config file")
						s.Options.Censys = false
					}
				}

				// SecurityTrails API key check
				if s.Options.SecurityTrails {
					if keys := config.ReadAPIKeys("securitytrails"); len(keys) > 0 && keys[0] != "" {
						color.Green("[*] SecurityTrails API found in the config filex")
					} else {
						color.Yellow("[!] SecurityTrails API could not find in the config file")
						s.Options.SecurityTrails = false
					}
				}

				// Shodan API key check
				if s.Options.Shodan {
					if keys := config.ReadAPIKeys("shodan"); len(keys) > 0 && keys[0] != "" {
						color.Green("[*] Shodan API found in the config filex")
					} else {
						color.Yellow("[!] Shodan API could not find in the config file")
						s.Options.Shodan = false
					}
				}

				// Zoomeye API key check
				if s.Options.Zoomeye {
					if keys := config.ReadAPIKeys("zoomeye"); len(keys) > 0 && keys[0] != "" {
						color.Green("[*] Zoomeye API found in the config filex")
					} else {
						color.Yellow("[!] Zoomeye API could not find in the config file")
						s.Options.Zoomeye = false
					}
				}

				color.White("\n[*] Scan has been started for targets...")
			}*/

		s.mu.Lock()
		s.Stats.TotalIPsScanned = 0
		s.Stats.RealIPsFound = 0
		s.mu.Unlock()

		if len(nonCFIPs) > 0 {
			s.checkARecords(url, nonCFIPs, cfIPs[0], actualHTMLTitle)
			s.mu.Lock()
			s.Stats.TotalIPsScanned += len(nonCFIPs)
			s.mu.Unlock()
		}

		s.getTXTRecords(domain, url, cfIPs[0], actualHTMLTitle)

		if s.Options.Censys {
			s.censysSearch(domain, url, cfIPs[0], actualHTMLTitle)
		}

		if s.Options.SecurityTrails {
			s.securityTrailsSearch(domain, url, cfIPs[0], actualHTMLTitle)
		}

		if s.Options.Shodan {
			s.shodanSearch(domain, url, cfIPs[0], actualHTMLTitle)
		}

		if s.Options.Zoomeye {
			s.zoomeyeSearch(domain, url, cfIPs[0], actualHTMLTitle)
		}

		if s.Options.DomainList != "" && s.Options.TargetDomain != "" {
			s.checkDomainList(url, cfIPs[1], actualHTMLTitle)
		}

		// Print final results only for the last domain
		if url == s.URLs[len(s.URLs)-1] {
			color.White("\n[*] Scan Results: %d Real IP(s) found.", s.Stats.RealIPsFound)
		}
	} else {
		color.Red("[!] %s is not behind Cloudflare. Skipping...", domain)
	}
}

func (s *Scanner) printDomains(url string) {
	domain := strings.Split(url, "//")[1]
	cfIPs, nonCFIPs := dns.GetARecords(domain)

	if s.Options.CF {
		if len(cfIPs) > 0 {
			fmt.Println(url)
		}
	}
	if s.Options.NCF {
		if len(nonCFIPs) > 0 {
			fmt.Println(url)
		}
	}
}

func (s *Scanner) checkDomainList(url string, cfIP net.IP, actualHTMLTitle string) {
	for _, d := range s.Domains {
		parseIt := strings.Split(d, "//")
		domain := parseIt[1]

		targetDomain := strings.Split(s.Options.TargetDomain, "//")[1]

		_, nonCFIPs := dns.GetARecords(domain)

		if len(nonCFIPs) > 0 {
			for _, ip := range nonCFIPs {
				htmlTitle := s.checkHTMLTitle("http://"+ip.String(), targetDomain)
				if htmlTitle == actualHTMLTitle {
					s.printResult(url, cfIP, ip, "DNS A Record", actualHTMLTitle)
				}
			}
		}
	}
}

func (s *Scanner) checkHTMLTitle(urlStr string, hostHeader string) string {
	// URL'den host kısmını çıkar
	parsedURL, err := neturl.Parse(urlStr)
	if err != nil {
		return ""
	}

	title, err := httpClient.GetHTMLTitleWithPortCheck(parsedURL.Host, s.Options.JA3, s.Options.UserAgent, s.Options.Proxy)
	if err != nil {
		return ""
	}
	return title
}

func (s *Scanner) getHTMLTitle(urlStr string) (string, error) {
	// URL'den host kısmını çıkar
	parsedURL, err := neturl.Parse(urlStr)
	if err != nil {
		return "", err
	}

	return httpClient.GetHTMLTitleWithPortCheck(parsedURL.Host, s.Options.JA3, s.Options.UserAgent, s.Options.Proxy)
}

func (s *Scanner) checkARecords(url string, ips []net.IP, cfIP net.IP, actualHTMLTitle string) {
	for _, ip := range ips {
		if s.Options.Verbose {
			color.Cyan("[*] Non-Cloudflare IP(%s) found in %s's A record. Checking it...", ip.String(), url)
		}
		s.compareTitle(url, ip, cfIP, "A - Record", actualHTMLTitle)
	}
}

func (s *Scanner) getTXTRecords(domain, url string, cfIP net.IP, actualHTMLTitle string) {
	txtRecords, err := dns.GetTXTRecords(domain)
	if err != nil {
		return
	}

	var extractedIPs []string
	for _, txt := range txtRecords {
		extractedIP := dns.ExtractIPAddresses(txt)
		if len(extractedIP) > 0 {
			for _, ipAddress := range extractedIP {
				if !strings.Contains(strings.Join(extractedIPs, ","), ipAddress) {
					extractedIPs = append(extractedIPs, ipAddress)
				}
			}

			for _, ipx := range extractedIPs {
				netIP := net.ParseIP(ipx)
				if netIP.To4() != nil {
					if s.Options.Verbose {
						color.Magenta("[*] Non-Cloudflare IP(%s) found in %s's TXT record. Checking it...", netIP.String(), domain)
					}
					s.compareTitle(url, netIP, cfIP, "TXT - DNS Record", actualHTMLTitle)
				}
			}
		}
	}
}

func (s *Scanner) censysSearch(domain, url string, cfIP net.IP, actualHTMLTitle string) {
	keys := config.ReadAPIKeys("censys")
	if len(keys) == 0 || keys[0] == "" {
		return
	}

	key := keys[0]
	keyToBytes := []byte(key)
	token := base64.StdEncoding.EncodeToString(keyToBytes)

	censysURL := "https://search.censys.io/api/v2/hosts/search?q=" + domain + "&per_page=50&virtual_hosts=EXCLUDE"
	client := httpClient.NewHTTPClient(s.Options.Proxy, url)
	resp, err := client.Do(httpClient.RequestBuilder(censysURL, token, s.Options.HTTPMethod, s.Options.UserAgent))
	if err != nil {
		if strings.Contains(err.Error(), "giving up after") {
			color.Yellow("[!] Censys API rate limit exceeded. Please try again later. (%s)", domain)
		} else {
			color.Yellow("[!] Error making request to Censys API: %v", err)
		}
		return
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		var errorResponse struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(bodyBytes, &errorResponse); err == nil {
			if strings.Contains(errorResponse.Message, "exceeded the usage limits") {
				color.Yellow("[!] Censys API rate limit exceeded: %s", errorResponse.Message)
			} else {
				color.Yellow("[!] Censys API error: %s", errorResponse.Message)
			}
		} else {
			color.Yellow("[!] Censys API returned non-200 status code %d: %s", resp.StatusCode, string(bodyBytes))
		}
		color.Yellow("[!] HTTP Status: %s", resp.Status)
		color.Yellow("[!] HTTP Headers:")
		for key, values := range resp.Header {
			for _, value := range values {
				color.Yellow("[!]   %s: %s", key, value)
			}
		}
		return
	}

	var data models.CensysJSON
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		color.Yellow("[!] Error decoding Censys response: %v", err)
		return
	}

	var stats struct {
		totalFound       int
		cloudflareIPs    int
		nonCloudflareIPs int
	}

	if !s.Options.Verbose {
		color.Cyan("\n[*] Censys search for %s started.", domain)
	} else {
		color.Cyan("\n[*] Censys search results for %s:", domain)
	}

	for _, cip := range data.Result.Hits {
		censysIP := net.ParseIP(cip.IP)
		if censysIP.To4() != nil {
			stats.totalFound++
			result, _ := dns.IsInCloudflareIPRange(censysIP)
			if s.Options.Verbose {
				if result {
					color.White("[+] IP: %s (Cloudflare)", censysIP)
				} else {
					color.Yellow("[+] IP: %s", censysIP)
				}
			}
			if result {
				stats.cloudflareIPs++
			} else {
				stats.nonCloudflareIPs++
				s.compareTitle(url, censysIP, cfIP, "Censys", actualHTMLTitle)
			}
		}
	}

	if !s.Options.Verbose {
		color.Cyan("[*] Censys search for %s completed. (Total %d IPs Found, %d IPs don't belong to Cloudflare)",
			domain, stats.totalFound, stats.nonCloudflareIPs)
	}
}

func (s *Scanner) securityTrailsSearch(domain, url string, cfIP net.IP, actualHTMLTitle string) {
	keys := config.ReadAPIKeys("securitytrails")
	if len(keys) == 0 {
		color.Yellow("[!] SecurityTrails API key not found in ~/.config/cf-hero.yaml")
		return
	}
	key := keys[0]
	if key == "" {
		color.Yellow("[!] SecurityTrails API key is empty in ~/.config/cf-hero.yaml")
		return
	}

	apiURL := fmt.Sprintf("https://api.securitytrails.com/v1/history/%s/dns/a", domain)
	client := httpClient.NewHTTPClient(s.Options.Proxy, url)

	req := httpClient.RequestBuilder(apiURL, "", s.Options.HTTPMethod, s.Options.UserAgent)
	req.Header.Set("APIKEY", key)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "giving up after") {
			color.Yellow("[!] SecurityTrails API rate limit exceeded. Please try again later. (%s)", domain)
		} else {
			color.Yellow("[!] Error making request to SecurityTrails API: %v", err)
		}
		return
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		var errorResponse struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(bodyBytes, &errorResponse); err == nil {
			if strings.Contains(errorResponse.Message, "exceeded the usage limits") {
				color.Yellow("[!] SecurityTrails API rate limit exceeded: %s", errorResponse.Message)
			} else {
				color.Yellow("[!] SecurityTrails API error: %s", errorResponse.Message)
			}
		} else {
			color.Yellow("[!] SecurityTrails API returned non-200 status code %d: %s", resp.StatusCode, string(bodyBytes))
		}
		color.Yellow("[!] HTTP Status: %s", resp.Status)
		color.Yellow("[!] HTTP Headers:")
		for key, values := range resp.Header {
			for _, value := range values {
				color.Yellow("[!]   %s: %s", key, value)
			}
		}
		return
	}

	var data models.SecurityTrailsResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		color.Yellow("[!] Error decoding SecurityTrails response: %v", err)
		return
	}

	var stats struct {
		totalFound       int
		cloudflareIPs    int
		nonCloudflareIPs int
	}

	if !s.Options.Verbose {
		color.Cyan("\n[*] SecurityTrails  DNS records for %s started.", domain)
	} else {
		color.Cyan("\n[*] SecurityTrails  DNS records for %s:", domain)
	}

	for _, record := range data.Records {
		org := "Unknown"
		if len(record.Organizations) > 0 {
			org = strings.Join(record.Organizations, ", ")
		}
		period := fmt.Sprintf("%s to %s", record.FirstSeen, record.LastSeen)

		for _, value := range record.Values {
			ip := net.ParseIP(value.IP)
			if ip != nil && ip.To4() != nil {
				stats.totalFound++
				result, _ := dns.IsInCloudflareIPRange(ip)
				if s.Options.Verbose {
					if result {
						color.White("[+] [IP: %s - Organization: %s - Period: %s] (Cloudflare)", value.IP, org, period)
					} else {
						color.Yellow("[+] [IP: %s - Organization: %s - Period: %s]", value.IP, org, period)
					}
				}
				if result {
					stats.cloudflareIPs++
				} else {
					stats.nonCloudflareIPs++
					s.compareTitle(url, ip, cfIP, "SecurityTrails", actualHTMLTitle)
				}
			}
		}
	}

	if !s.Options.Verbose {
		color.Cyan("[*] SecurityTrails DNS records for %s completed. (Total %d IPs Found, %d IPs don't belong to Cloudflare)",
			domain, stats.totalFound, stats.nonCloudflareIPs)
	}
}

func (s *Scanner) shodanSearch(domain, url string, cfIP net.IP, actualHTMLTitle string) {
	keys := config.ReadAPIKeys("shodan")
	if len(keys) == 0 {
		color.Yellow("[!] Shodan API key not found in ~/.config/cf-hero.yaml")
		return
	}
	key := keys[0]
	if key == "" {
		color.Yellow("[!] Shodan API key is empty in ~/.config/cf-hero.yaml")
		return
	}

	maxRetries := 5
	retryCount := 0
	var resp *http.Response
	var err error

	apiURL := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s&history=true", domain, key)
	client := httpClient.NewHTTPClient(s.Options.Proxy, url)
	req := httpClient.RequestBuilder(apiURL, "", s.Options.HTTPMethod, s.Options.UserAgent)
	req.Header.Set("Accept", "application/json")

	// Retry loop
	for retryCount < maxRetries {
		resp, err = client.Do(req)
		if err == nil && resp.StatusCode == 200 {
			break
		}

		if resp != nil {
			resp.Body.Close()
		}

		retryCount++
		if retryCount == maxRetries {
			color.Red("[-] Error making request to Shodan API after %d retries: %v\n", maxRetries, err)
			return
		}

		// Exponential backoff: 1s, 2s, 4s, 8s, 16s
		waitTime := time.Duration(1<<uint(retryCount-1)) * time.Second
		color.Yellow("[!] Retrying Shodan API request in %v (attempt %d/%d)...\n", waitTime, retryCount, maxRetries)
		time.Sleep(waitTime)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		color.Yellow("[!] Shodan API returned non-200 status code %d: %s\n", resp.StatusCode, string(bodyBytes))
		return
	}

	var data models.ShodanDNSHistoryResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		color.Yellow("[!] Error decoding Shodan response: %v\n", err)
		return
	}

	var stats struct {
		totalFound       int
		cloudflareIPs    int
		nonCloudflareIPs int
	}

	if s.Options.Verbose {
		color.Cyan("\n[*] Shodan DNS records for %s started.", domain)
	}

	for _, record := range data.Data {
		if record.Type == "A" {
			ip := net.ParseIP(record.Value)
			if ip != nil && ip.To4() != nil {
				stats.totalFound++
				result, _ := dns.IsInCloudflareIPRange(ip)
				if s.Options.Verbose {
					if result {
						color.White("[+] IP: %s (First seen: %s, Last seen: %s) (Cloudflare)",
							record.Value, record.FirstSeen, record.LastSeen)
					} else {
						color.Yellow("[+] IP: %s (First seen: %s, Last seen: %s)",
							record.Value, record.FirstSeen, record.LastSeen)
					}
				}
				if result {
					stats.cloudflareIPs++
				} else {
					stats.nonCloudflareIPs++
					s.compareTitle(url, ip, cfIP, "Shodan", actualHTMLTitle)
				}
			}
		}
	}

	if !s.Options.Verbose {
		color.Cyan("[*] Shodan DNS records for %s completed. (Total %d IPs Found, %d IPs don't belong to Cloudflare)",
			domain, stats.totalFound, stats.nonCloudflareIPs)
	}
}

func (s *Scanner) zoomeyeSearch(domain, url string, cfIP net.IP, actualHTMLTitle string) {
	keys := config.ReadAPIKeys("zoomeye")
	if len(keys) == 0 {
		color.Yellow("[!] ZoomEye API key not found in ~/.config/cf-hero.yaml")
		return
	}
	key := keys[0]
	if key == "" {
		color.Yellow("[!] ZoomEye API key is empty in ~/.config/cf-hero.yaml")
		return
	}

	// Base64 encode the query
	query := fmt.Sprintf("domain=%s", domain)
	queryBase64 := base64.StdEncoding.EncodeToString([]byte(query))

	page := 1
	resultsPerPage := 20
	var totalResults int
	var stats struct {
		totalFound       int
		cloudflareIPs    int
		nonCloudflareIPs int
		testedIPs        int
	}

	for {
		// Prepare request body
		requestBody := map[string]interface{}{
			"qbase64": queryBase64,
			"page":    page,
		}
		jsonBody, err := json.Marshal(requestBody)
		if err != nil {
			color.Red("[-] Error preparing ZoomEye request body: %v\n", err)
			return
		}

		zoomeyeURL := "https://api.zoomeye.ai/v2/search"
		client := httpClient.NewHTTPClient(s.Options.Proxy, url)

		req, err := http.NewRequest("POST", zoomeyeURL, strings.NewReader(string(jsonBody)))
		if err != nil {
			color.Red("[-] Error creating ZoomEye request: %v\n", err)
			return
		}

		req.Header.Set("API-KEY", key)
		req.Header.Set("User-Agent", s.Options.UserAgent)

		resp, err := client.Do(req)
		if err != nil {
			color.Red("[-] Error making request to ZoomEye API: %v\n", err)
			return
		}

		// Check response status
		if resp.StatusCode != 200 {
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			color.Yellow("[!] ZoomEye API returned non-200 status code %d: %s\n", resp.StatusCode, string(bodyBytes))
			return
		}

		var data models.ZoomeyeResponse
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			resp.Body.Close()
			color.Red("[-] Error decoding ZoomEye response: %v\n", err)
			return
		}
		resp.Body.Close()

		// Set total results on first page
		if page == 1 {
			totalResults = data.Total
			if s.Options.Verbose {
				color.Cyan("\n[*] ZoomEye search results for %s (Total: %d):", domain, totalResults)
			}
		}

		s.mu.Lock()
		s.Stats.TotalIPsScanned += len(data.Data)
		s.mu.Unlock()

		// Process results for current page
		for _, result := range data.Data {
			zoomeyeIP := net.ParseIP(result.IP)
			if zoomeyeIP.To4() != nil {
				stats.totalFound++

				// Convert port from json.RawMessage to int
				var port int
				if err := json.Unmarshal(result.Port, &port); err != nil {
					// Try to unmarshal as string first
					var portStr string
					if err := json.Unmarshal(result.Port, &portStr); err != nil {
						color.Red("[-] Error converting port %s to int: %v\n", string(result.Port), err)
						continue
					}
					// Convert string to int
					port, err = strconv.Atoi(portStr)
					if err != nil {
						color.Red("[-] Error converting port string %s to int: %v\n", portStr, err)
						continue
					}
				}

				isCloudflare, _ := dns.IsInCloudflareIPRange(zoomeyeIP)
				if s.Options.Verbose {
					if isCloudflare {
						color.White("[+] IP: %s (Port: %d, Domain: %s, Updated: %s) (Cloudflare)",
							result.IP, port, result.Domain, result.UpdateTime)
					} else {
						color.Yellow("[+] IP: %s (Port: %d, Domain: %s, Updated: %s)",
							result.IP, port, result.Domain, result.UpdateTime)
					}
				}
				if isCloudflare {
					stats.cloudflareIPs++
				} else {
					stats.nonCloudflareIPs++
					stats.testedIPs++
					s.compareTitle(url, zoomeyeIP, cfIP, "ZoomEye", actualHTMLTitle)
				}
			}
		}

		// Check if we need to fetch more pages
		if page*resultsPerPage >= totalResults {
			break
		}
		page++
	}

	if !s.Options.Verbose {
		color.Cyan("[*] ZoomEye search for %s completed. (Total %d IPs Found, %d IPs don't belong to Cloudflare)",
			domain, stats.totalFound, stats.nonCloudflareIPs)
	}
}

func (s *Scanner) compareTitle(url string, ip net.IP, cfIP net.IP, source string, actualHTMLTitle string) {
	foundIPTitle, _ := httpClient.GetHTMLTitleWithPortCheck(ip.String(), s.Options.JA3, s.Options.UserAgent, s.Options.Proxy)

	if actualHTMLTitle == foundIPTitle {
		s.mu.Lock()
		s.Stats.RealIPsFound++
		s.mu.Unlock()
		s.printResult(url, cfIP, ip, source, actualHTMLTitle)
	}
}

func (s *Scanner) printResult(url string, cfIP net.IP, realIP interface{}, source, htmlTitle string) {
	color.Green("[+] Found real IP of %s : %v (Source: %s) - Title: %s", url, realIP, source, htmlTitle)
}

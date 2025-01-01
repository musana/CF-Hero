package scanner

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"strings"
	"sync"
	"time"

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
		Total     int
		Behind    int
		NotBehind int
	}
}

func New(options *models.Options, urls []string, domains []string) *Scanner {
	return &Scanner{
		Options: options,
		URLs:    urls,
		Domains: domains,
	}
}

func (s *Scanner) PreScan() {
	fmt.Println("\n[*] Pre-scanning domains to identify Cloudflare protected ones...")
	total := len(s.URLs)
	processed := 0

	fmt.Print("\r[*] Pre-Scanning: 0/" + fmt.Sprint(total))

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
			fmt.Print("\r[*] Progress: " + fmt.Sprint(processed) + "/" + fmt.Sprint(total))
			s.mu.Unlock()
		})
	}

	wg.Wait()
	wp.StopWait()

	fmt.Printf("\n[+] Found %d/%d domains behind Cloudflare\n\n", s.Stats.Behind, s.Stats.Total)

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

	domain := strings.Split(url, "//")[1]
	cfIPs, nonCFIPs := dns.GetARecords(domain)

	if len(cfIPs) > 0 {
		actualHTMLTitle, _ := s.getHTMLTitle(url)

		if len(nonCFIPs) > 0 {
			s.checkARecords(url, nonCFIPs, cfIPs[0], actualHTMLTitle)
			fmt.Println("Found:", "URL", url, "CF IP", cfIPs, "NON-CF-IP:", nonCFIPs)
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

		if s.Options.DomainList != "" && s.Options.TargetDomain != "" {
			s.checkDomainList(url, cfIPs[1], actualHTMLTitle)
		}

		if s.Bar != nil {
			s.Bar.Add(1)
		}
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
					s.compareTitle(url, netIP, cfIP, "TXT - DNS Record", actualHTMLTitle)
				}
			}
		}
	}
}

func (s *Scanner) censysSearch(domain, url string, cfIP net.IP, actualHTMLTitle string) {
	key := config.ReadAPIKeys("censys")[0]
	keyToBytes := []byte(key)
	token := base64.StdEncoding.EncodeToString(keyToBytes)

	censysURL := "https://search.censys.io/api/v2/hosts/search?q=" + domain + "&per_page=50&virtual_hosts=EXCLUDE"
	client := httpClient.NewHTTPClient(s.Options.Proxy, url)
	resp, err := client.Do(httpClient.RequestBuilder(censysURL, token, s.Options.HTTPMethod, s.Options.UserAgent))
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var data models.CensysJSON
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return
	}

	for _, cip := range data.Result.Hits {
		censysIP := net.ParseIP(cip.IP)
		if censysIP.To4() != nil {
			result, _ := dns.IsInCloudflareIPRange(censysIP)
			if !result {
				s.compareTitle(url, censysIP, cfIP, "Censys", actualHTMLTitle)
			}
		}
	}
}

func (s *Scanner) securityTrailsSearch(domain, url string, cfIP net.IP, actualHTMLTitle string) {
	keys := config.ReadAPIKeys("securitytrails")
	if len(keys) == 0 {
		fmt.Println("[!] SecurityTrails API key not found in ~/.config/cf-hero.yaml")
		return
	}
	key := keys[0]
	if key == "" {
		fmt.Println("[!] SecurityTrails API key is empty in ~/.config/cf-hero.yaml")
		return
	}

	apiURL := fmt.Sprintf("https://api.securitytrails.com/v1/history/%s/dns/a", domain)
	client := httpClient.NewHTTPClient(s.Options.Proxy, url)

	req := httpClient.RequestBuilder(apiURL, "", s.Options.HTTPMethod, s.Options.UserAgent)
	req.Header.Set("APIKEY", key)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[!] Error making request to SecurityTrails API: %v\n", err)
		return
	}
	defer resp.Body.Close()

	var data models.SecurityTrailsResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		fmt.Printf("[!] Error decoding SecurityTrails response: %v\n", err)
		return
	}

	fmt.Printf("\n[*] SecurityTrails historical DNS records for %s:\n", domain)
	for _, record := range data.Records {
		for _, value := range record.Values {
			//fmt.Printf("[+] IP: %s (First seen: %s, Last seen: %s)\n",
			//	value.IP, record.FirstSeen, record.LastSeen)

			ip := net.ParseIP(value.IP)
			if ip != nil && ip.To4() != nil {
				result, _ := dns.IsInCloudflareIPRange(ip)
				if !result {
					s.compareTitle(url, ip, cfIP, "SecurityTrails", actualHTMLTitle)
				}
			}
		}
	}
	fmt.Println()
}

func (s *Scanner) shodanSearch(domain, url string, cfIP net.IP, actualHTMLTitle string) {
	keys := config.ReadAPIKeys("shodan")
	if len(keys) == 0 {
		fmt.Println("[!] Shodan API key not found in ~/.config/cf-hero.yaml")
		return
	}
	key := keys[0]
	if key == "" {
		fmt.Println("[!] Shodan API key is empty in ~/.config/cf-hero.yaml")
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
			fmt.Printf("[!] Error making request to Shodan API after %d retries: %v\n", maxRetries, err)
			return
		}

		// Exponential backoff: 1s, 2s, 4s, 8s, 16s
		waitTime := time.Duration(1<<uint(retryCount-1)) * time.Second
		fmt.Printf("[*] Retrying Shodan API request in %v (attempt %d/%d)...\n", waitTime, retryCount, maxRetries)
		time.Sleep(waitTime)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		fmt.Printf("[!] Shodan API returned non-200 status code %d: %s\n", resp.StatusCode, string(bodyBytes))
		return
	}

	var data models.ShodanDNSHistoryResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		fmt.Printf("[!] Error decoding Shodan response: %v\n", err)
		return
	}

	fmt.Printf("\n[*] Shodan historical DNS records for %s:\n", domain)
	for _, record := range data.Data {
		if record.Type == "A" {
			fmt.Printf("[+] IP: %s (First seen: %s, Last seen: %s)\n",
				record.Value, record.FirstSeen, record.LastSeen)

			ip := net.ParseIP(record.Value)
			if ip != nil && ip.To4() != nil {
				result, _ := dns.IsInCloudflareIPRange(ip)
				if !result {
					s.compareTitle(url, ip, cfIP, "Shodan", actualHTMLTitle)
				}
			}
		}
	}
	fmt.Println()
}

func (s *Scanner) compareTitle(url string, ip net.IP, cfIP net.IP, source string, actualHTMLTitle string) {
	foundIPTitle, _ := httpClient.GetHTMLTitleWithPortCheck(ip.String(), s.Options.JA3, s.Options.UserAgent, s.Options.Proxy)

	if actualHTMLTitle == foundIPTitle {
		s.printResult(url, cfIP, ip, source, actualHTMLTitle)
	}
}

func (s *Scanner) printResult(url string, cfIP net.IP, realIP interface{}, source, htmlTitle string) {
	// ANSI color codes
	colors := struct {
		green   string
		cyan    string
		yellow  string
		red     string
		blue    string
		magenta string
		reset   string
		bold    string
	}{
		green:   "\033[32m",
		cyan:    "\033[36m",
		yellow:  "\033[33m",
		red:     "\033[31m",
		blue:    "\033[34m",
		magenta: "\033[35m",
		reset:   "\033[0m",
		bold:    "\033[1m",
	}

	banner := `
╭─────────────────────────────────────────────────────────────
│ %s%s[!] Real IP Found%s
├─────────────────────────────────────────────────────────────
│ %s%s Target Domain%s    │ %s%s%s			
│ %s%s CloudFlare IP%s    │ %s%s%s
│ %s%s Real IP%s          │ %s%v%s
│ %s%s Source%s           │ %s%s%s
│ %s%s HTML Title%s       │ %s%s%s
╰─────────────────────────────────────────────────────────────
`
	fmt.Printf(banner,
		colors.bold, colors.green, colors.reset,
		colors.bold, colors.blue, colors.reset, colors.yellow, url, colors.reset,
		colors.bold, colors.blue, colors.reset, colors.yellow, cfIP, colors.reset,
		colors.bold, colors.blue, colors.reset, colors.yellow, realIP, colors.reset,
		colors.bold, colors.blue, colors.reset, colors.magenta, source, colors.reset,
		colors.bold, colors.blue, colors.reset, colors.cyan, htmlTitle, colors.reset,
	)
}

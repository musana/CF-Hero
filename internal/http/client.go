package http

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Danny-Dasilva/CycleTLS/cycletls"
	"github.com/hashicorp/go-retryablehttp"
	"golang.org/x/net/html"
)

func NewHTTPClient(proxy string, urlx string) *http.Client {
	tr := &http.Transport{
		MaxIdleConns:        20,
		MaxConnsPerHost:     20,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     time.Second * 2,
		DisableKeepAlives:   true,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   time.Second * 2,
			KeepAlive: time.Second * 2,
		}).DialContext,
	}

	if proxy != "" {
		if p, err := url.Parse(proxy); err == nil {
			tr.Proxy = http.ProxyURL(p)
		}
	}

	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 2
	retryClient.RetryWaitMax = time.Second * 1
	retryClient.Logger = nil
	retryClient.HTTPClient.Transport = tr
	httpClient := retryClient.StandardClient()

	return httpClient
}

func RequestBuilderWithHost(url, hostHeader, httpMethod, userAgent string) *http.Request {
	req, _ := http.NewRequest(httpMethod, url, nil)
	req.Header.Add("User-Agent", userAgent)
	req.Header.Add("Connection", "Close")
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Host = hostHeader

	return req
}

func RequestBuilder(url, token, httpMethod, userAgent string) *http.Request {
	req, _ := http.NewRequest(httpMethod, url, nil)
	req.Header.Add("User-Agent", userAgent)
	req.Header.Add("Connection", "Close")
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	//req.Header.Add("Authorization", "Basic "+token)

	return req
}

func CycleTLSforJA3(url, ja3, userAgent, proxy string) (cycletls.Response, error) {
	client := cycletls.Init()

	response, err := client.Do(url, cycletls.Options{
		Body:            "",
		Ja3:             ja3,
		UserAgent:       userAgent,
		Timeout:         5,
		Proxy:           proxy,
		DisableRedirect: false,
		Headers:         map[string]string{},
	}, "GET")

	return response, err
}

func GetHTMLTitle(doc *html.Node) string {
	var title string
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "title" && n.FirstChild != nil {
			title = n.FirstChild.Data
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}
	traverse(doc)
	return title
}

// CheckPort checks if a port is open on a host
func CheckPort(host string, port string) bool {
	timeout := time.Second * 2
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return false
	}
	if conn != nil {
		conn.Close()
		return true
	}
	return false
}

// GetHTMLTitleWithPortCheck tries to get HTML title with port checking
func GetHTMLTitleWithPortCheck(ip string, ja3, userAgent, proxy string) (string, error) {
	// First try HTTP (port 80)
	if CheckPort(ip, "80") {
		resp, err := CycleTLSforJA3("http://"+ip, ja3, userAgent, proxy)
		if err == nil && resp.Body != "" {
			reader := strings.NewReader(resp.Body)
			doc, err := html.Parse(reader)
			if err == nil {
				title := GetHTMLTitle(doc)
				if title != "" {
					return title, nil
				}
			}
		}
	}

	// If HTTP fails or returns empty title, try HTTPS (port 443)
	if CheckPort(ip, "443") {
		resp, err := CycleTLSforJA3("https://"+ip, ja3, userAgent, proxy)
		if err == nil && resp.Body != "" {
			reader := strings.NewReader(resp.Body)
			doc, err := html.Parse(reader)
			if err == nil {
				title := GetHTMLTitle(doc)
				if title != "" {
					return title, nil
				}
			}
		}
	}

	// Try with standard HTTP client to follow redirects
	client := NewHTTPClient(proxy, "")
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		return nil
	}

	// Try HTTP first
	if CheckPort(ip, "80") {
		resp, err := client.Get("http://" + ip)
		if err == nil {
			defer resp.Body.Close()
			doc, err := html.Parse(resp.Body)
			if err == nil {
				title := GetHTMLTitle(doc)
				if title != "" {
					return title, nil
				}
			}
		}
	}

	// Try HTTPS if HTTP fails
	if CheckPort(ip, "443") {
		resp, err := client.Get("https://" + ip)
		if err == nil {
			defer resp.Body.Close()
			doc, err := html.Parse(resp.Body)
			if err == nil {
				title := GetHTMLTitle(doc)
				if title != "" {
					return title, nil
				}
			}
		}
	}

	return "", fmt.Errorf("no accessible ports found or no title available")
}

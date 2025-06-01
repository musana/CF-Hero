package http

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Danny-Dasilva/CycleTLS/cycletls"
	"golang.org/x/net/html"
)

func NewHTTPClient(proxy string, targetURL string) *http.Client {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DisableKeepAlives:     false,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	if proxy != "" {
		transport.Proxy = http.ProxyFromEnvironment
	}

	return &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}
}

func RequestBuilder(url string, token string, method string, userAgent string) *http.Request {
	req, _ := http.NewRequest(method, url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Basic "+token)
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Connection", "keep-alive")
	return req
}

func RequestBuilderWithHost(url, hostHeader, httpMethod, userAgent string) *http.Request {
	req, _ := http.NewRequest(httpMethod, url, nil)
	req.Header.Add("User-Agent", userAgent)
	req.Header.Add("Connection", "Close")
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Host = hostHeader

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

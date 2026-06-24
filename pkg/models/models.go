package models

import (
	"encoding/json"
)

type Options struct {
	File           string
	Worker         int
	Version        bool
	HTTPMethod     string
	UserAgent      string
	Proxy          string
	DomainList     string
	TargetDomain   string
	JA3            string
	CF             bool
	NCF            bool
	Censys         bool
	SecurityTrails bool
	Shodan         bool
	Zoomeye        bool
	Verbose        bool
	Title          string
}

// CensysPlatformResponse models the Censys Platform API
// (POST https://api.platform.censys.io/v3/global/search/query) response.
// The legacy search.censys.io v2 API has been deprecated.
type CensysPlatformResponse struct {
	Result struct {
		Hits []struct {
			HostV1 *struct {
				Resource struct {
					IP string `json:"ip"`
				} `json:"resource"`
			} `json:"host_v1"`
		} `json:"hits"`
		NextPageToken string `json:"next_page_token"`
		TotalHits     int    `json:"total_hits"`
	} `json:"result"`
}

type SecurityTrailsResponse struct {
	Endpoint string `json:"endpoint"`
	Pages    int    `json:"pages"`
	Records  []struct {
		Values []struct {
			IP      string `json:"ip"`
			IPCount int    `json:"ip_count"`
		} `json:"values"`
		Type          string   `json:"type"`
		FirstSeen     string   `json:"first_seen"`
		LastSeen      string   `json:"last_seen"`
		Organizations []string `json:"organizations"`
	} `json:"records"`
	Type string `json:"type"`
}

type ShodanDNSHistoryResponse struct {
	Domain string `json:"domain"`
	Data   []struct {
		Subdomain string `json:"subdomain"`
		Type      string `json:"type"`
		Value     string `json:"value"`
		Ports     []int  `json:"ports"`
		LastSeen  string `json:"last_seen"`
	} `json:"data"`
}

type ZoomeyeResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Query   string `json:"query"`
	Total   int    `json:"total"`
	Data    []struct {
		IP         string          `json:"ip"`
		Port       json.RawMessage `json:"port"`
		Domain     string          `json:"domain"`
		UpdateTime string          `json:"update_time"`
	} `json:"data"`
	Facets map[string]interface{} `json:"facets"`
}

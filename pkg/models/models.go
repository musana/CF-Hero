package models

import (
	"encoding/json"
	"time"
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

type CensysJSON struct {
	Code   int    `json:"code"`
	Status string `json:"status"`
	Result struct {
		Hits []struct {
			IP            string    `json:"ip"`
			LastUpdatedAt time.Time `json:"last_updated_at"`
		} `json:"hits"`
		Links struct {
			Next string `json:"next"`
			Prev string `json:"prev"`
		} `json:"links"`
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
	Data []struct {
		Type      string `json:"type"`
		Value     string `json:"value"`
		LastSeen  string `json:"last_seen"`
		FirstSeen string `json:"first_seen"`
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

package models

import "time"

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
	Records []struct {
		Values []struct {
			IP string `json:"ip"`
		} `json:"values"`
		Type      string `json:"type"`
		FirstSeen string `json:"first_seen"`
		LastSeen  string `json:"last_seen"`
	} `json:"records"`
	Meta struct {
		TotalRecords int `json:"total_records"`
	} `json:"meta"`
}

type ShodanDNSHistoryResponse struct {
	Data []struct {
		Type      string `json:"type"`
		Value     string `json:"value"`
		LastSeen  string `json:"last_seen"`
		FirstSeen string `json:"first_seen"`
	} `json:"data"`
}

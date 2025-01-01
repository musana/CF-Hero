package config

import (
	"fmt"
	"os"

	"github.com/musana/cf-hero/pkg/models"
	"github.com/projectdiscovery/goflags"
	"gopkg.in/yaml.v2"
)

func ParseOptions() *models.Options {
	options := &models.Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Exposing real IPs of been domain behind of Cloudflare`)

	createGroup(flagSet, "General Options", "GENERAL OPTIONS",
		flagSet.IntVar(&options.Worker, "w", 16, "Worker count"),
		flagSet.StringVar(&options.File, "f", "", "Input file containing list of host/domain"),
	)

	createGroup(flagSet, "print options", "PRINT OPTIONS",
		flagSet.BoolVar(&options.CF, "cf", false, "Print domains behind of Cloudflare"),
		flagSet.BoolVar(&options.NCF, "non-cf", false, "Print domains is not behind of Cloudflare"),
	)

	createGroup(flagSet, "sources", "SOURCES",
		flagSet.BoolVar(&options.Censys, "censys", false, "Include Censys in scan"),
		flagSet.BoolVar(&options.SecurityTrails, "securitytrails", false, "Include SecurityTrails historical DNS records in scan"),
		flagSet.BoolVar(&options.Shodan, "shodan", false, "Include Shodan historical DNS records in scan"),
		flagSet.StringVar(&options.DomainList, "dl", "", "Domain list for sub/domain scan"),
		flagSet.StringVar(&options.TargetDomain, "td", "", "Target domain for sub/domain scan"),
	)

	createGroup(flagSet, "configuration", "CONFIGURATION",
		flagSet.StringVar(&options.HTTPMethod, "hm", "GET", "HTTP method."),
		flagSet.StringVar(&options.JA3, "ja3", "772,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,18-10-16-23-45-35-5-11-13-65281-0-51-43-17513-27,29-23-24,0", "JA3 String"),
		flagSet.StringVar(&options.UserAgent, "ua", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/113.0", "HTTP User-Agent"),
		flagSet.StringVar(&options.Proxy, "px", "", "HTTP proxy to use"),
	)

	_ = flagSet.Parse()

	return options
}

func createGroup(flagSet *goflags.FlagSet, groupName, description string, flags ...*goflags.FlagData) {
	flagSet.SetGroup(groupName, description)
	for _, currentFlag := range flags {
		currentFlag.Group(groupName)
	}
}

func ReadAPIKeys(source string) []string {
	home := os.Getenv("HOME")
	if home == "" {
		home = os.Getenv("USERPROFILE") // Windows için
	}

	configPath := home + "/.config/cf-hero.yaml"
	f, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Printf("[!] Error reading config file %s: %v\n", configPath, err)
		return nil
	}

	var apiKeys map[string][]string
	err = yaml.Unmarshal(f, &apiKeys)
	if err != nil {
		fmt.Printf("[!] Error parsing YAML from %s: %v\n", configPath, err)
		return nil
	}

	keys, ok := apiKeys[source]
	if !ok {
		fmt.Printf("[!] No API keys found for source '%s' in %s\n", source, configPath)
		return nil
	}

	return keys
}

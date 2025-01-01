package main

import (
	"fmt"
	"os"

	"github.com/gammazero/workerpool"
	"github.com/musana/cf-hero/internal/config"
	"github.com/musana/cf-hero/internal/scanner"
	"github.com/musana/cf-hero/internal/utils"
)

func main() {
	fmt.Print(utils.Banner())

	options := config.ParseOptions()
	var urls []string
	var domainList []string

	if options.File != "" && options.DomainList == "" {
		urls = utils.ReadFromFile(options.File)
	} else if options.File == "" && options.DomainList != "" {
		urls = append(urls, options.TargetDomain)
		domainList = utils.ReadFromFile(options.DomainList)
	} else {
		fi, _ := os.Stdin.Stat()
		if fi.Mode()&os.ModeNamedPipe == 0 {
			fmt.Println("[!] No data found in pipe. Urls must be given using pipe or f parameter!")
			os.Exit(1)
		} else {
			urls = utils.ReadFromStdin()
		}
	}

	scanner := scanner.New(options, urls, domainList)
	scanner.PreScan()

	wp := workerpool.New(options.Worker)
	for _, url := range urls {
		url := url
		wp.Submit(func() {
			scanner.Start(url)
		})
	}
	wp.StopWait()
}

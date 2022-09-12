package generate

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"

	"github.com/ipinfo/go/v2/ipinfo"
	"github.com/projectdiscovery/cdncheck"
)

var cidrRegex = regexp.MustCompile(`[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,3}`)

// Compile returns the compiled form of an input structure
func (i *Input) Compile(options *Options) (*cdncheck.InputCompiled, error) {
	compiled := &cdncheck.InputCompiled{
		CDN:   make(map[string][]string),
		WAF:   make(map[string][]string),
		Cloud: make(map[string][]string),
	}
	// Fetch input items specified
	if i.CDN != nil {
		if err := i.CDN.fetchInputItem(options, compiled.CDN); err != nil {
			log.Printf("[err] could not fetch cdn item: %s\n", err)
		}
	}
	if i.WAF != nil {
		if err := i.WAF.fetchInputItem(options, compiled.WAF); err != nil {
			log.Printf("[err] could not fetch waf item: %s\n", err)
		}
	}
	if i.Cloud != nil {
		if err := i.Cloud.fetchInputItem(options, compiled.Cloud); err != nil {
			log.Printf("[err] could not fetch cloud item: %s\n", err)
		}
	}

	// Fetch custom scraper data and merge
	for dataType, scraper := range scraperTypeToScraperMap {
		var data map[string][]string

		switch dataType {
		case "cdn":
			data = compiled.CDN
		case "waf":
			data = compiled.WAF
		case "cloud":
			data = compiled.Cloud
		default:
			panic(fmt.Sprintf("invalid datatype %s specified", dataType))
		}
		for _, item := range scraper {
			if response, err := item.scraper(options.HTTP()); err != nil {
				log.Printf("[err] could not scrape %s item: %s\n", item.name, err)
			} else {
				data[item.name] = response
			}
		}
	}
	return compiled, nil
}

// fetchInputItem fetches input items and writes data to map
func (i *InputItem) fetchInputItem(options *Options, data map[string][]string) error {
	for provider, cidrs := range i.CIDR {
		data[provider] = cidrs
	}
	for provider, urls := range i.URLs {
		for _, item := range urls {
			if cidrs, err := getCIDRFromURL(options.HTTP(), item); err != nil {
				return fmt.Errorf("could not get url %s: %s", item, err)
			} else {
				data[provider] = cidrs
			}
		}
	}
	// Only scrape ASN if we have an ID
	if !options.HasAuthInfo() {
		return nil
	}
	for provider, asn := range i.ASN {
		for _, item := range asn {
			if cidrs, err := getIpInfoASN(options.HTTP(), options.IPInfoToken, item); err != nil {
				return fmt.Errorf("could not get asn %s: %s", item, err)
			} else {
				data[provider] = cidrs
			}
		}
	}
	return nil
}

var errNoCidrFound = errors.New("no cidrs found for url")

// getIpInfoASN returns cidrs for an ASN from ipinfo using a token
func getIpInfoASN(httpClient *http.Client, token string, asn string) ([]string, error) {
	if token == "" {
		return nil, errors.New("ipinfo auth token not specified")
	}
	ipinfoClient := ipinfo.NewClient(httpClient, nil, token)
	info, err := ipinfoClient.GetASNDetails(asn)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, errNoCidrFound
	}
	var cidrs []string
	for _, prefix := range info.Prefixes {
		cidrs = append(cidrs, prefix.Netblock)
	}
	if len(cidrs) == 0 {
		return nil, errNoCidrFound
	}
	return cidrs, nil
}

// getCIDRFromURL scrapes CIDR ranges for a URL using a regex
func getCIDRFromURL(httpClient *http.Client, url string) ([]string, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	body := string(data)

	cidrs := cidrRegex.FindAllString(body, -1)
	if len(cidrs) == 0 {
		return nil, errNoCidrFound
	}
	return cidrs, nil
}

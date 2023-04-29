package generate

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"

	"github.com/PuerkitoBio/goquery"
	"github.com/ipinfo/go/v2/ipinfo"
	"github.com/projectdiscovery/cdncheck"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

var cidrRegex = regexp.MustCompile(`[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,3}`)

// Compile returns the compiled form of an input structure
func (c *Categories) Compile(options *Options) (*cdncheck.InputCompiled, error) {
	compiled := &cdncheck.InputCompiled{
		CDN:    make(map[string][]string),
		WAF:    make(map[string][]string),
		Cloud:  make(map[string][]string),
		Common: make(map[string][]string),
	}
	// Fetch input items specified
	if c.CDN != nil {
		if err := c.CDN.fetchInputItem(options, compiled.CDN); err != nil {
			log.Printf("[err] could not fetch cdn item: %s\n", err)
		}
	}
	if c.WAF != nil {
		if err := c.WAF.fetchInputItem(options, compiled.WAF); err != nil {
			log.Printf("[err] could not fetch waf item: %s\n", err)
		}
	}
	if c.Cloud != nil {
		if err := c.Cloud.fetchInputItem(options, compiled.Cloud); err != nil {
			log.Printf("[err] could not fetch cloud item: %s\n", err)
		}
	}
	if c.Common != nil {
		compiled.Common = c.Common.FQDN
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
			if response, err := item.scraper(http.DefaultClient); err != nil {
				log.Printf("[err] could not scrape %s item: %s\n", item.name, err)
			} else {
				data[item.name] = response
			}
		}
	}
	return compiled, nil
}

// fetchInputItem fetches input items and writes data to map
func (c *Category) fetchInputItem(options *Options, data map[string][]string) error {
	for provider, cidrs := range c.CIDR {
		data[provider] = cidrs
	}
	for provider, urls := range c.URLs {
		for _, item := range urls {
			if cidrs, err := getCIDRFromURL(item); err != nil {
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
	for provider, asn := range c.ASN {
		for _, item := range asn {
			if cidrs, err := getIpInfoASN(http.DefaultClient, options.IPInfoToken, item); err != nil {
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
func getCIDRFromURL(URL string) ([]string, error) {
	retried := false
retry:
	req, err := http.NewRequest(http.MethodGet, URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// if the body type is HTML, retry with the first json link in the page (special case for Azure download page to find changing URLs)
	if resp.Header.Get("Content-Type") == "text/html" && !retried {
		var extractedURL string
		docReader, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		docReader.Find("a").Each(func(i int, item *goquery.Selection) {
			src, ok := item.Attr("href")
			if ok && stringsutil.ContainsAny(src, "ServiceTags_Public_") && extractedURL == "" {
				extractedURL = src
			}
		})
		URL = extractedURL
		retried = true
		goto retry
	}

	body := string(data)

	cidrs := cidrRegex.FindAllString(body, -1)
	if len(cidrs) == 0 {
		return nil, errNoCidrFound
	}
	return cidrs, nil
}

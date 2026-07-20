package generate

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"regexp"

	"github.com/PuerkitoBio/goquery"
	"github.com/ipinfo/go/v2/ipinfo"
	"github.com/projectdiscovery/cdncheck"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

var cidrRegex = regexp.MustCompile(`(([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,3})|(((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\/[0-9]{1,3}))`)

func getValidateCidrs(cidrs []string) []string {
	var output []string

	for _, cidr := range cidrs {
		_, err := netip.ParsePrefix(cidr)
		if err == nil {
			output = append(output, cidr)
		} else {
			fmt.Printf("skipping '%v' err: %v\n", cidr, err)
		}
	}

	return output
}

// Compile returns the compiled form of an input structure.
//
// Per-provider/per-source failures are accumulated and returned as a joined
// error. The compiled result is still returned alongside the error so callers
// can decide whether to use a partially populated dataset.
func (c *Categories) Compile(options *Options) (*cdncheck.InputCompiled, error) {
	compiled := &cdncheck.InputCompiled{
		CDN:    make(map[string][]string),
		WAF:    make(map[string][]string),
		Cloud:  make(map[string][]string),
		Common: make(map[string][]string),
	}
	var errs []error
	if c.CDN != nil {
		if err := c.CDN.fetchInputItem(options, compiled.CDN); err != nil {
			log.Printf("[err] cdn: %s\n", err)
			errs = append(errs, fmt.Errorf("cdn: %w", err))
		}
	}
	if c.WAF != nil {
		if err := c.WAF.fetchInputItem(options, compiled.WAF); err != nil {
			log.Printf("[err] waf: %s\n", err)
			errs = append(errs, fmt.Errorf("waf: %w", err))
		}
	}
	if c.Cloud != nil {
		if err := c.Cloud.fetchInputItem(options, compiled.Cloud); err != nil {
			log.Printf("[err] cloud: %s\n", err)
			errs = append(errs, fmt.Errorf("cloud: %w", err))
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
				log.Printf("[err] scraper %s/%s: %s\n", dataType, item.name, err)
				errs = append(errs, fmt.Errorf("scraper %s/%s: %w", dataType, item.name, err))
			} else {
				data[item.name] = appendUniqueCIDRs(data[item.name], response)
			}
		}
	}
	return compiled, errors.Join(errs...)
}

// fetchInputItem fetches input items and writes data to map.
//
// On per-item failure the loop continues so a single unreachable URL or ASN
// does not drop the rest of the providers in this category. All errors are
// joined and returned at the end. Multiple URLs/ASNs declared for the same
// provider are merged (deduped) instead of overwritten.
func (c *Category) fetchInputItem(options *Options, data map[string][]string) error {
	var errs []error
	for provider, cidrs := range c.CIDR {
		data[provider] = appendUniqueCIDRs(data[provider], cidrs)
	}
	for provider, urls := range c.URLs {
		for _, item := range urls {
			cidrs, err := getCIDRFromURL(item)
			if err != nil {
				log.Printf("[err] url %s (%s): %s\n", provider, item, err)
				errs = append(errs, fmt.Errorf("url %s (%s): %w", provider, item, err))
				continue
			}
			data[provider] = appendUniqueCIDRs(data[provider], cidrs)
		}
	}
	if !options.HasAuthInfo() {
		return errors.Join(errs...)
	}
	for provider, asn := range c.ASN {
		for _, item := range asn {
			cidrs, err := getIpInfoASN(http.DefaultClient, options.IPInfoToken, item)
			if err != nil {
				log.Printf("[err] asn %s (%s): %s\n", provider, item, err)
				errs = append(errs, fmt.Errorf("asn %s (%s): %w", provider, item, err))
				continue
			}
			data[provider] = appendUniqueCIDRs(data[provider], cidrs)
		}
	}
	return errors.Join(errs...)
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
	for _, prefix := range info.Prefixes6 {
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
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// if the body type is HTML, retry with the first json link in the page (special case for Azure download page to find changing URLs)
	if stringsutil.ContainsAnyI(resp.Header.Get("Content-Type"), "text/html") && !retried {
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
	return getValidateCidrs(cidrs), nil
}

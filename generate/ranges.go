package generate

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type scraperNameFuncPair struct {
	name    string
	scraper scraperFunc
}

var scraperTypeToScraperMap = map[string][]scraperNameFuncPair{
	"cdn": {
		{name: "cloudfront", scraper: scrapeCloudFront},
	},
	"waf": {
		{name: "incapsula", scraper: scrapeIncapsula},
	},
	"cloud": {},
}

type scraperFunc func(httpClient *http.Client) ([]string, error)

// scrapeIncapsula scrapes incapsula firewall's CIDR ranges from their API
func scrapeIncapsula(httpClient *http.Client) ([]string, error) {
	req, err := http.NewRequest(http.MethodPost, "https://my.incapsula.com/api/integration/v1/ips", strings.NewReader("resp_format=text"))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
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
	body := string(data)

	cidrs := cidrRegex.FindAllString(body, -1)
	if len(cidrs) == 0 {
		return nil, errNoCidrFound
	}
	return getValidateCidrs(cidrs), nil
}

// scrapeCloudFront scrapes CloudFront's CIDR ranges from AWS ip-ranges.json.
//
// The CloudFront list configured in provider.yaml is IPv4 only, so without
// this the IPv6 edges of a dual-stack distribution only match cloud/aws.
func scrapeCloudFront(httpClient *http.Client) ([]string, error) {
	resp, err := httpClient.Get("https://ip-ranges.amazonaws.com/ip-ranges.json")
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}
	return parseAWSServiceCIDRs(resp.Body, "CLOUDFRONT")
}

// parseAWSServiceCIDRs returns the IPv4 and IPv6 prefixes of an AWS service.
// It filters by service because the generic URL source would extract every
// AWS range from ip-ranges.json.
func parseAWSServiceCIDRs(r io.Reader, service string) ([]string, error) {
	var ranges struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Service  string `json:"service"`
		} `json:"prefixes"`
		IPv6Prefixes []struct {
			IPv6Prefix string `json:"ipv6_prefix"`
			Service    string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.NewDecoder(r).Decode(&ranges); err != nil {
		return nil, err
	}
	var cidrs []string
	for _, p := range ranges.Prefixes {
		if p.Service == service {
			cidrs = append(cidrs, p.IPPrefix)
		}
	}
	for _, p := range ranges.IPv6Prefixes {
		if p.Service == service {
			cidrs = append(cidrs, p.IPv6Prefix)
		}
	}
	if len(cidrs) == 0 {
		return nil, errNoCidrFound
	}
	return getValidateCidrs(cidrs), nil
}

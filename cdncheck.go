package cdncheck

import (
	"net"
	"strings"
	"sync"

	"github.com/projectdiscovery/retryabledns"
)

var (
	DefaultCDNProviders   string
	DefaultWafProviders   string
	DefaultCloudProviders string
)

// Client checks for CDN based IPs which should be excluded
// during scans since they belong to third party firewalls.
type Client struct {
	sync.Once
	cdn          *providerScraper
	waf          *providerScraper
	cloud        *providerScraper
	retriabledns *retryabledns.Client
}

// New creates a new firewall IP checking client.
func New() *Client {
	defaultResolvers := []string{"8.8.8.8", "8.8.0.0"}
	defaultMaxRetries := 3
	retryabledns, err := retryabledns.New(defaultResolvers, defaultMaxRetries)
	if err != nil {
		return nil
	}
	client := &Client{
		cdn:          newProviderScraper(generatedData.CDN),
		waf:          newProviderScraper(generatedData.WAF),
		cloud:        newProviderScraper(generatedData.Cloud),
		retriabledns: retryabledns,
	}
	return client
}

// CheckCDN checks if an IP is contained in the cdn denylist
func (c *Client) CheckCDN(ip net.IP) (matched bool, value string, err error) {
	matched, value, err = c.cdn.Match(ip)
	return matched, value, err
}

// CheckWAF checks if an IP is contained in the waf denylist
func (c *Client) CheckWAF(ip net.IP) (matched bool, value string, err error) {
	matched, value, err = c.waf.Match(ip)
	return matched, value, err
}

// CheckCloud checks if an IP is contained in the cloud denylist
func (c *Client) CheckCloud(ip net.IP) (matched bool, value string, err error) {
	matched, value, err = c.cloud.Match(ip)
	return matched, value, err
}

// Check checks if an IP is contained in the denylist
//
// It includes CDN, WAF and Cloud. Basically all varaint of individual functions
func (c *Client) Check(ip net.IP) (matched bool, value string, itemType string, err error) {
	if matched, value, err = c.cdn.Match(ip); err == nil && matched && value != "" {
		return matched, value, "cdn", nil
	}
	if matched, value, err = c.waf.Match(ip); err == nil && matched && value != "" {
		return matched, value, "waf", nil
	}
	if matched, value, err = c.cloud.Match(ip); err == nil && matched && value != "" {
		return matched, value, "cloud", nil
	}
	return false, "", "", err
}

// Check checks if a Domain is contained in the denylist
//
// It includes CDN, WAF and Cloud. Basically all varaint of individual functions
//
// It uses DNS queries to check for Ip's and CNAMES
func (c *Client) CheckDomainWithFallback(domain string) (matched bool, value string, itemType string, err error) {
	dnsData, err := c.retriabledns.Resolve(domain)
	if err != nil {
		return false, "", "", err
	}
	matched, value, itemType, err = c.CheckDNSResponse(dnsData)
	if err != nil {
		return false, "", "", err
	}
	if matched {
		return matched, value, itemType, nil
	}
	// resolve cname
	dnsData, err = c.retriabledns.CNAME(domain)
	if err != nil {
		return false, "", "", err
	}
	return c.CheckDNSResponse(dnsData)
}

// Check checks if dnsResponse is contained in the denylist
//
// It includes CDN, WAF and Cloud. Basically all varaint of individual functions
//
// It's useful to prevent Additional DNS queries
func (c *Client) CheckDNSResponse(dnsResponse *retryabledns.DNSData) (matched bool, value string, itemType string, err error) {
	if dnsResponse.A != nil {
		for _, ip := range dnsResponse.A {
			ipAddr := net.ParseIP(ip)
			if ipAddr == nil {
				continue
			}
			matched, value, itemType, err := c.Check(ipAddr)
			if err != nil {
				return false, "", "", err
			}
			if matched {
				return matched, value, itemType, nil
			}
		}
	}
	if dnsResponse.CNAME != nil {
		matched, discovered, err := c.CheckSuffix(dnsResponse.CNAME...)
		if err != nil {
			return false, "", "", err
		}
		if matched {
			// for now checkSuffix only checks for wafs
			return matched, discovered, "waf", nil
		}
	}
	return false, "", "", err
}

func mapKeys(m map[string][]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return strings.Join(keys, ", ")
}

package cdncheck

import (
	"net"
	"strings"
	"sync"
)

var (
	DefaultCDNProviders   = mapKeys(generatedData.CDN)
	DefaultWafProviders   = mapKeys(generatedData.WAF)
	DefaultCloudProviders = mapKeys(generatedData.Cloud)
)

// Client checks for CDN based IPs which should be excluded
// during scans since they belong to third party firewalls.
type Client struct {
	sync.Once
	cdn   *providerScraper
	waf   *providerScraper
	cloud *providerScraper
}

// New creates a new firewall IP checking client.
func New() *Client {
	client := &Client{
		cdn:   newProviderScraper(generatedData.CDN),
		waf:   newProviderScraper(generatedData.WAF),
		cloud: newProviderScraper(generatedData.Cloud),
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

func mapKeys(m map[string][]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return strings.Join(keys, ", ")
}

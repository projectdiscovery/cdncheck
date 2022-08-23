package cdncheck

import "net"

// Client checks for CDN based IPs which should be excluded
// during scans since they belong to third party firewalls.
type Client struct {
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

// GetDefaultProviders exports default providers
func GetDefaultCdnProviders() []string {
	var provider []string
	for k := range generatedData.CDN {
		provider = append(provider, k)
	}
	return provider
}

func GetDefaultCloudProviders() []string {
	var provider []string
	for k := range generatedData.Cloud {
		provider = append(provider, k)
	}
	return provider
}

func GetDefaultWafProviders() []string {
	var provider []string
	for k := range generatedData.WAF {
		provider = append(provider, k)
	}
	return provider
}

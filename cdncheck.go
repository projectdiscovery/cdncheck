package cdncheck

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/yl2chen/cidranger"
)

// Client checks for CDN based IPs which should be excluded
// during scans since they belong to third party firewalls.
type Client struct {
	rangers map[string]cidranger.Ranger
}

var defaultScrapers = map[string]scraperFunc{
	"akamai":     scrapeAkamai,
	"azure":      scrapeAzure,
	"cloudflare": scrapeCloudflare,
	"cloudfront": scrapeCloudFront,
	"fastly":     scrapeFastly,
	"incapsula":  scrapeIncapsula,
	"sucuri":     scrapeSucuri,
	"leaseweb":   scrapeLeaseweb,
}

var cachedScrapers = map[string]scraperFunc{
	"projectdiscovery": scrapeProjectDiscovery,
}

// New creates a new firewall IP checking client.
func New() (*Client, error) {
	return new(false)
}

// NewWithCache creates a new firewall IP with cached data from project discovery (faster)
func NewWithCache() (*Client, error) {
	return new(true)
}

func new(cache bool) (*Client, error) {
	httpClient := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			TLSClientConfig: &tls.Config{
				Renegotiation:      tls.RenegotiateOnceAsClient,
				InsecureSkipVerify: true,
			},
		},
		Timeout: time.Duration(30) * time.Second,
	}
	client := &Client{}

	var scrapers map[string]scraperFunc
	if cache {
		scrapers = cachedScrapers
	} else {
		scrapers = defaultScrapers
	}

	client.rangers = make(map[string]cidranger.Ranger)
	for provider, scraper := range scrapers {
		cidrs, err := scraper(httpClient)
		if err != nil {
			return nil, err
		}

		ranger := cidranger.NewPCTrieRanger()
		for _, cidr := range cidrs {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			ranger.Insert(cidranger.NewBasicRangerEntry(*network))
		}
		client.rangers[provider] = ranger
	}
	return client, nil
}

// Check checks if an IP is contained in the blacklist
func (c *Client) Check(ip net.IP) (bool, string, error) {
	for provider, ranger := range c.rangers {
		if contains, err := ranger.Contains(ip); contains {
			return true, provider, err
		}
	}
	return false, "", nil
}

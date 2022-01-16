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
	Options Options
	Data    map[string]struct{}
	ranger  cidranger.Ranger
}

var defaultScrapers = map[string]scraperFunc{
	// "akamai":     scrapeAkamai,
	"azure":      scrapeAzure,
	"cloudflare": scrapeCloudflare,
	"cloudfront": scrapeCloudFront,
	"fastly":     scrapeFastly,
	"incapsula":  scrapeIncapsula,
	// "sucuri":     scrapeSucuri,
	// "leaseweb":   scrapeLeaseweb,
}

var defaultScrapersWithOptions = map[string]scraperWithOptionsFunc{
	"akamai":   scrapeAkamai,
	"sucuri":   scrapeSucuri,
	"leaseweb": scrapeLeaseweb,
}

var cachedScrapers = map[string]scraperFunc{
	"projectdiscovery": scrapeProjectDiscovery,
}

// New creates a new firewall IP checking client.
func New() (*Client, error) {
	return new(&Options{})
}

// NewWithCache creates a new firewall IP with cached data from project discovery (faster)
func NewWithCache() (*Client, error) {
	return new(&Options{Cache: true})
}

// NewWithOptions creates a new instance with options
func NewWithOptions(Options *Options) (*Client, error) {
	return new(Options)
}

func new(options *Options) (*Client, error) {
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

	if options.Cache {
		for _, scraper := range cachedScrapers {
			cidrs, err := scraper(httpClient)
			if err != nil {
				return nil, err
			}
			client.parseCidrs(cidrs)
		}
	} else {
		for _, scraper := range defaultScrapers {
			cidrs, err := scraper(httpClient)
			if err != nil {
				return nil, err
			}
			client.parseCidrs(cidrs)
		}
	}

	if options.HasAuthInfo() {
		for _, scraper := range defaultScrapersWithOptions {
			cidrs, err := scraper(httpClient, options)
			if err != nil {
				return nil, err
			}
			client.parseCidrs(cidrs)
		}
	}

	ranger := cidranger.NewPCTrieRanger()
	for cidr := range client.Data {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		ranger.Insert(cidranger.NewBasicRangerEntry(*network))
	}
	client.ranger = ranger

	return client, nil
}

// parseCidrs inserts the scraped cidrs to the internal structure
func (c *Client) parseCidrs(cidrs []string) {
	if c.Data == nil {
		c.Data = make(map[string]struct{})
	}
	for _, cidr := range cidrs {
		c.Data[cidr] = struct{}{}
	}
}

// Check checks if an IP is contained in the blacklist
func (c *Client) Check(ip net.IP) (bool, error) {
	return c.ranger.Contains(ip)
}

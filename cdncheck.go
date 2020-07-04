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
	ranger cidranger.Ranger
}

var scrapers = map[string]scraperFunc{
	"akamai":     scrapeAkamai,
	"cloudflare": scrapeCloudflare,
	"incapsula":  scrapeIncapsula,
	"sucuri":     scrapeSucuri,
}

// New creates a new firewall IP checking client.
func New() (*Client, error) {
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

	dups := make(map[string]struct{})
	for _, scraper := range scrapers {
		cidrs, err := scraper(httpClient)
		if err != nil {
			return nil, err
		}
		for _, cidr := range cidrs {
			if _, ok := dups[cidr]; !ok {
				dups[cidr] = struct{}{}
			}
		}
	}

	ranger := cidranger.NewPCTrieRanger()
	for cidr := range dups {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		ranger.Insert(cidranger.NewBasicRangerEntry(*network))
	}
	client.ranger = ranger

	return client, nil
}

// Check checks if an IP is contained in the blacklist
func (c *Client) Check(ip net.IP) (bool, error) {
	return c.ranger.Contains(ip)
}

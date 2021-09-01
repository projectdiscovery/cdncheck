package cdncheck

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestScrapeRanges(t *testing.T) {
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

	t.Run("azure", func(t *testing.T) {
		ips, err := scrapeAzure(httpClient)
		require.Nil(t, err, "Could not scrape azure")
		require.Positive(t, len(ips), "Empty ip list")
	})
	t.Run("cloudfront", func(t *testing.T) {
		ips, err := scrapeCloudFront(httpClient)
		require.Nil(t, err, "Could not scrape cloudfront")
		require.Positive(t, len(ips), "Empty ip list")
	})
	t.Run("cloudflare", func(t *testing.T) {
		ips, err := scrapeCloudflare(httpClient)
		require.Nil(t, err, "Could not scrape cloudflare")
		require.Positive(t, len(ips), "Empty ip list")
	})
	t.Run("incapsula", func(t *testing.T) {
		ips, err := scrapeIncapsula(httpClient)
		require.Nil(t, err, "Could not scrape incapsula")
		require.Positive(t, len(ips), "Empty ip list")
	})
	t.Run("fastly", func(t *testing.T) {
		ips, err := scrapeFastly(httpClient)
		require.Nil(t, err, "Could not scrape fastly")
		require.Positive(t, len(ips), "Empty ip list")
	})
	t.Run("projectdiscovery", func(t *testing.T) {
		ips, err := scrapeProjectDiscovery(httpClient)
		require.Nil(t, err, "Could not scrape projectdiscovery")
		require.Positive(t, len(ips), "Empty ip list")
	})
}

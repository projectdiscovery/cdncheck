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

	t.Run("cloudflare", func(t *testing.T) {
		_, err := scrapeCloudflare(httpClient)
		require.Nil(t, err, "Could not scrape cloudflare")
	})
	t.Run("cloudfront", func(t *testing.T) {
		_, err := scrapeCloudFront(httpClient)
		require.Nil(t, err, "Could not scrape cloudfront")
	})
	t.Run("incapsula", func(t *testing.T) {
		_, err := scrapeIncapsula(httpClient)
		require.Nil(t, err, "Could not scrape incapsula")
	})
	t.Run("akamai", func(t *testing.T) {
		_, err := scrapeAkamai(httpClient)
		require.Nil(t, err, "Could not scrape akamai")
	})
	t.Run("sucuri", func(t *testing.T) {
		_, err := scrapeSucuri(httpClient)
		require.Nil(t, err, "Could not scrape sucuri")
	})
	t.Run("fastly", func(t *testing.T) {
		_, err := scrapeFastly(httpClient)
		require.Nil(t, err, "Could not scrape fastly")
	})
	t.Run("projectdiscovery", func(t *testing.T) {
		_, err := scrapeProjectDiscovery(httpClient)
		require.Nil(t, err, "Could not scrape projectdiscovery")
	})
}

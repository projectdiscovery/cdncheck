package generate

import (
	"crypto/tls"
	"net/http"
	"os"
	"time"
)

var defaultHttpClient = &http.Client{
	Transport: &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		TLSClientConfig: &tls.Config{
			Renegotiation:      tls.RenegotiateOnceAsClient,
			InsecureSkipVerify: true,
		},
	},
	Timeout: time.Duration(30) * time.Second,
}

type Options struct {
	IPInfoToken string
	HTTPClient  *http.Client
}

// HTTP returns the HTTP client instance
func (options *Options) HTTP() *http.Client {
	if options.HTTPClient == nil {
		return defaultHttpClient
	}
	return options.HTTPClient
}

// HasAuthInfo returns true if auth info has been provided
func (options *Options) HasAuthInfo() bool {
	return options.IPInfoToken != ""
}

// ParseFromEnv parses auth tokens from env or file
func (options *Options) ParseFromEnv() {
	if ipInfoToken := os.Getenv("IPINFO_TOKEN"); ipInfoToken != "" {
		options.IPInfoToken = ipInfoToken
	}
}

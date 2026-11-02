package generate

import (
	"net/http"
	"os"
)

type Options struct {
	IPInfoToken string
	PDCPApiKey  string
	HTTPClient  *http.Client
}

// HasAuthInfo returns true if auth info has been provided
func (options *Options) HasAuthInfo() bool {
	return options.IPInfoToken != "" || options.PDCPApiKey != ""
}

// ParseFromEnv parses auth tokens from env or file
func (options *Options) ParseFromEnv() {
	if ipInfoToken := os.Getenv("IPINFO_TOKEN"); ipInfoToken != "" {
		options.IPInfoToken = ipInfoToken
	}
	if pdcpKey := os.Getenv("PDCP_API_KEY"); pdcpKey != "" {
		options.PDCPApiKey = pdcpKey
	}
	if pdKey := os.Getenv("PD_API_KEY"); pdKey != "" && options.PDCPApiKey == "" {
		options.PDCPApiKey = pdKey
	}
}

package generate

import (
	"net/http"
	"os"
)

type Options struct {
	IPInfoToken string
	HTTPClient  *http.Client
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

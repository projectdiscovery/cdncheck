package cdncheck

import (
	"os"
)

type Options struct {
	Cache       bool
	IPInfoToken string
}

func (options *Options) HasAuthInfo() bool {
	return options.IPInfoToken != ""
}

// ParseFromEnv parses auth tokens from env or file
func (options *Options) ParseFromEnv() {
	if ipInfoToken := os.Getenv("IPINFO_TOKEN"); ipInfoToken != "" {
		options.IPInfoToken = ipInfoToken
	}
}

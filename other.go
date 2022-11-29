package cdncheck

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

// cdnCnameDomains contains a map of CNAME to domains to cdns
var cdnCnameDomains = map[string]string{
	"cloudfront.net":         "amazon",
	"amazonaws.com":          "amazon",
	"edgekey.net":            "akamai",
	"akamaiedge.net":         "akamai",
	"akamaitechnologies.com": "akamai",
	"akamaihd.net":           "akamai",
	"cloudflare.com":         "cloudflare",
	"fastly.net":             "fastly",
	"edgecastcdn.net":        "edgecast",
	"impervadns.net":         "incapsula",
}

// cdnWappalyzerTechnologies contains a map of wappalyzer technologies to cdns
var cdnWappalyzerTechnologies = map[string]string{
	"imperva":    "imperva",
	"incapsula":  "incapsula",
	"cloudflare": "cloudflare",
	"cloudfront": "amazon",
	"akamai":     "akamai",
}

// CheckCNAME checks if the CNAMEs are a part of CDN
func (c *Client) CheckCNAME(cnames []string) (bool, string, error) {
	for _, cname := range cnames {
		parsed, err := publicsuffix.Parse(cname)
		if err != nil {
			return false, "", errors.Wrap(err, "could not parse cname domain")
		}
		if discovered, ok := cdnCnameDomains[parsed.TLD]; ok {
			return true, discovered, nil
		}
		domain := parsed.SLD + "." + parsed.TLD
		if discovered, ok := cdnCnameDomains[domain]; ok {
			return true, discovered, nil
		}
	}
	return false, "", nil
}

// CheckWappalyzer checks if the wappalyzer detection are a part of CDN
func (c *Client) CheckWappalyzer(data map[string]struct{}) (bool, string, error) {
	for technology := range data {
		if strings.Contains(technology, ":") {
			if parts := strings.SplitN(technology, ":", 2); len(parts) == 2 {
				technology = parts[0]
			}
		}
		technology = strings.ToLower(technology)
		if discovered, ok := cdnWappalyzerTechnologies[technology]; ok {
			return true, discovered, nil
		}
	}
	return false, "", nil
}

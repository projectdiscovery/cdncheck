package cdncheck

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

var suffixToSource map[string]string

// cdnWappalyzerTechnologies contains a map of wappalyzer technologies to cdns
var cdnWappalyzerTechnologies = map[string]string{
	"imperva":    "imperva",
	"incapsula":  "incapsula",
	"cloudflare": "cloudflare",
	"cloudfront": "amazon",
	"akamai":     "akamai",
	"fastly":     "fastly",
	"sucuri":     "sucuri",
	"reblaze":    "reblaze",
	"stackpath":  "stackpath",
	"bunny":      "bunny",
	"bunnycdn":   "bunny",
	"cdn77":      "cdn77",
	"keycdn":     "keycdn",
	"vercel":     "vercel",
	"netlify":    "netlify",
	"azure cdn":  "azure",
	"cachefly":   "cachefly",
	"edgecast":   "edgecast",
	"limelight":  "limelight",
	"ddos-guard": "ddos-guard",
	"arvancloud": "arvancloud",
	"qrator":     "qrator",
	"section.io": "section.io",
	"f5 big-ip":                   "f5",
	"f5 big-ip access policy manager": "f5",
	"f5 big-ip local traffic manager": "f5",
	"f5 big-ip application security manager": "f5",
	"f5 distributed cloud":        "f5",
}

// CheckFQDN checks if fqdns are known cloud ones
func (c *Client) CheckSuffix(fqdns ...string) (isCDN bool, provider string, itemType string, err error) {
	c.Do(func() {
		suffixToSource = make(map[string]string)
		for source, suffixes := range generatedData.Common {
			for _, suffix := range suffixes {
				suffixToSource[suffix] = source
			}
		}
	})
	for _, fqdn := range fqdns {
		if _, err := publicsuffix.Parse(fqdn); err != nil {
			return false, "", "", errors.Wrap(err, "could not parse fqdn")
		}
		trimmed := strings.ToLower(strings.TrimSuffix(fqdn, "."))
		parts := strings.Split(trimmed, ".")
		for i := 0; i < len(parts); i++ {
			candidate := strings.Join(parts[i:], ".")
			if discovered, ok := suffixToSource[candidate]; ok {
				return true, discovered, "waf", nil
			}
		}
	}
	return false, "", "", nil
}

// CheckWappalyzer checks if the wappalyzer detection are a part of CDN
func (c *Client) CheckWappalyzer(data map[string]struct{}) (isCDN bool, provider string, err error) {
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

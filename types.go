package cdncheck

import (
	"net"
	"net/netip"

	"github.com/gaissmai/bart"
)

// InputCompiled contains a compiled list of input structure
type InputCompiled struct {
	// CDN contains a list of ranges for CDN cidrs
	CDN map[string][]string `yaml:"cdn,omitempty" json:"cdn,omitempty"`
	// WAF contains a list of ranges for WAF cidrs
	WAF map[string][]string `yaml:"waf,omitempty" json:"waf,omitempty"`
	// Cloud contains a list of ranges for Cloud cidrs
	Cloud map[string][]string `yaml:"cloud,omitempty" json:"cloud,omitempty"`
	// Common contains a list of suffixes for major sources
	Common map[string][]string `yaml:"common,omitempty" json:"common,omitempty"`
}

// providerScraper is a structure for scraping providers
type providerScraper struct {
	rangers map[string]*bart.Table[netip.Prefix]
}

// newProviderScraper returns a new provider scraper instance
func newProviderScraper(ranges map[string][]string) *providerScraper {
	scraper := &providerScraper{rangers: make(map[string]*bart.Table[netip.Prefix])}

	for provider, items := range ranges {
		ranger := new(bart.Table[netip.Prefix])
		for _, cidr := range items {
			if network, err := netip.ParsePrefix(cidr); err == nil {
				// Keep the prefix itself as the value so that Match can tell how
				// specific each hit was.
				ranger.Insert(network, network)
			}
		}
		scraper.rangers[provider] = ranger
	}
	return scraper
}

// Match returns true if the IP matches provided CIDR ranges.
//
// Several providers can claim the same address (the generated data contains
// overlapping ranges, such as 1.31.128.0/24 belonging to both aliyun and
// jiasule, or azure's 13.107.4.0/22 enclosing office365's 13.107.6.152/31), and
// the providers are stored in a map. Returning the first hit therefore reported
// a provider that changed from run to run and made -mcdn/-mcloud filtering
// unreliable. Pick the most specific prefix instead and break ties by provider
// name so the result is stable.
func (p *providerScraper) Match(ip net.IP) (bool, string, error) {
	parsed, err := netip.ParseAddr(ip.String())
	if err != nil {
		return false, "", err
	}

	var (
		matchedProvider string
		matchedBits     = -1
	)
	for provider, ranger := range p.rangers {
		prefix, contains := ranger.Lookup(parsed)
		if !contains {
			continue
		}
		bits := prefix.Bits()
		if bits > matchedBits || (bits == matchedBits && provider < matchedProvider) {
			matchedProvider, matchedBits = provider, bits
		}
	}
	if matchedBits >= 0 {
		return true, matchedProvider, nil
	}
	return false, "", nil
}

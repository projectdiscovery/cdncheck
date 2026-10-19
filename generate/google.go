package generate

import (
	"net/netip"
	"sort"

	"github.com/projectdiscovery/cdncheck"
)

// googleProvider is the provider key used by both the google CDN source
// (goog.json) and the google cloud source (cloud.json).
const googleProvider = "google"

// excludeGoogleCloudFromCDN removes Google Cloud customer ranges from the
// google CDN ranges.
//
// goog.json lists every IP range Google owns, including the ranges it assigns
// to Google Cloud customers (Compute Engine VMs, load balancers). Since CDN is
// matched before cloud, a customer's VM would otherwise be reported as a
// google CDN edge. Google documents the ranges of its own services as goog.json
// minus cloud.json:
// https://cloud.google.com/vpc/docs/configure-private-google-access#ip-addr-defaults
//
// When either source is missing (for example, a failed fetch), the CDN ranges
// are left unchanged.
func excludeGoogleCloudFromCDN(compiled *cdncheck.InputCompiled) error {
	cdnCIDRs, cloudCIDRs := compiled.CDN[googleProvider], compiled.Cloud[googleProvider]
	if len(cdnCIDRs) == 0 || len(cloudCIDRs) == 0 {
		return nil
	}
	remaining, err := subtractCIDRs(cdnCIDRs, cloudCIDRs)
	if err != nil {
		return err
	}
	compiled.CDN[googleProvider] = remaining
	return nil
}

// subtractCIDRs returns the address space of from that is not covered by
// remove, as a sorted list of CIDRs.
func subtractCIDRs(from, remove []string) ([]string, error) {
	fromPrefixes, err := parsePrefixes(from)
	if err != nil {
		return nil, err
	}
	removePrefixes, err := parsePrefixes(remove)
	if err != nil {
		return nil, err
	}
	var output []string
	for _, prefix := range fromPrefixes {
		for _, remaining := range subtractPrefix(prefix, removePrefixes) {
			output = append(output, remaining.String())
		}
	}
	sort.Strings(output)
	return output, nil
}

// subtractPrefix splits prefix in halves until each part is either fully
// removed or does not overlap any prefix in remove.
func subtractPrefix(prefix netip.Prefix, remove []netip.Prefix) []netip.Prefix {
	var overlapping []netip.Prefix
	for _, candidate := range remove {
		if !candidate.Overlaps(prefix) {
			continue
		}
		if candidate.Bits() <= prefix.Bits() {
			return nil // candidate covers the whole prefix
		}
		overlapping = append(overlapping, candidate)
	}
	if len(overlapping) == 0 {
		return []netip.Prefix{prefix}
	}
	lower, upper := splitPrefix(prefix)
	return append(subtractPrefix(lower, overlapping), subtractPrefix(upper, overlapping)...)
}

// splitPrefix returns the two halves of prefix, which must be masked and
// shorter than the full address length.
func splitPrefix(prefix netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := prefix.Bits() + 1
	address := prefix.Addr().AsSlice()
	address[prefix.Bits()/8] |= 0x80 >> (prefix.Bits() % 8)
	upper, _ := netip.AddrFromSlice(address)
	return netip.PrefixFrom(prefix.Addr(), bits), netip.PrefixFrom(upper, bits)
}

func parsePrefixes(cidrs []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

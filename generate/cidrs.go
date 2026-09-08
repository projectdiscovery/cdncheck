package generate

// appendUniqueCIDRs merges cidrs into existing, preserving order and
// dropping duplicates already present in either slice.
func appendUniqueCIDRs(existing, cidrs []string) []string {
	if len(cidrs) == 0 {
		return existing
	}
	seen := make(map[string]struct{}, len(existing)+len(cidrs))
	for _, cidr := range existing {
		seen[cidr] = struct{}{}
	}
	out := append([]string(nil), existing...)
	for _, cidr := range cidrs {
		if _, ok := seen[cidr]; ok {
			continue
		}
		seen[cidr] = struct{}{}
		out = append(out, cidr)
	}
	return out
}

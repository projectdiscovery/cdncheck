package generate

// Categories contains various cdn, waf, cloud and fqdn operators
type Categories struct {
	// CDN contains a list of inputs for CDN cidrs
	CDN *Category `yaml:"cdn"`
	// WAF contains a list of inputs for WAF cidrs
	WAF *Category `yaml:"waf"`
	// Cloud contains a list of inputs for Cloud cidrs
	Cloud  *Category `yaml:"cloud"`
	Common *Category `yaml:"common"`
}

// Category contains configuration for a specific category
type Category struct {
	// URLs contains a list of static URLs for CIDR list
	URLs map[string][]string `yaml:"urls"`
	// ASN contains ASN numbers for an Input item
	ASN map[string][]string `yaml:"asn"`
	// CIDR contains a list of CIDRs for Input item
	//
	// CIDR is generated using generate-index tool which is then
	// used for checking the provided IP for each input type.
	CIDR map[string][]string `yaml:"cidr"`
	// FQDN contains public suffixes for major cloud operators
	FQDN map[string][]string `yaml:"fqdn"`
}

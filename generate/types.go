package generate

// Input is an input for the cdncheck generate tool
type Input struct {
	// CDN contains a list of inputs for CDN cidrs
	CDN *InputItem `yaml:"cdn" json:"cdn,omitempty"`
	// WAF contains a list of inputs for WAF cidrs
	WAF *InputItem `yaml:"waf" json:"waf,omitempty"`
	// Cloud contains a list of inputs for Cloud cidrs
	Cloud *InputItem `yaml:"cloud" json:"cloud,omitempty"`
}

// InputItem is a single item from input of cdncheck generate tool
type InputItem struct {
	// URLs contains a list of static URLs for CIDR list
	URLs map[string][]string `yaml:"urls"`
	// ASN contains ASN numbers for an Input item
	ASN map[string][]string `yaml:"asn"`
	// CIDR contains a list of CIDRs for Input item
	//
	// CIDR is generated using generate-index tool which is then
	// used for checking the provided IP for each input type.
	CIDR map[string][]string `yaml:"cidr"`
}


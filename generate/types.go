package generate

// Input is an input for the cdncheck generate tool
type Input struct {
	// CDN contains a list of inputs for CDN cidrs
	CDN *InputItem `yaml:"cdn"`
	// WAF contains a list of inputs for WAF cidrs
	WAF *InputItem `yaml:"waf"`
	// Cloud contains a list of inputs for Cloud cidrs
	Cloud *InputItem `yaml:"cloud"`
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

// CidrDataOutput is the output of the generate-index tool
type CidrDataOutput struct {
	// CDN contains a list of ranges for CDN cidrs
	CDN map[string][]string `json:"cdn,omitempty"`
	// WAF contains a list of ranges for WAF cidrs
	WAF map[string][]string `json:"waf,omitempty"`
	// Cloud contains a list of ranges for Cloud cidrs
	Cloud map[string][]string `json:"cloud,omitempty"`
}

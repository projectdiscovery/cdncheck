package cdncheck

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed sources_data.json
var data string

var generatedData InputCompiled

func init() {
	if err := json.Unmarshal([]byte(data), &generatedData); err != nil {
		panic(fmt.Sprintf("Could not parse cidr data: %s", err))
	}
	DefaultCDNProviders = mapKeys(generatedData.CDN)
	DefaultWafProviders = mapKeys(generatedData.WAF)
	if !strings.Contains(DefaultWafProviders, "citrix-netscaler") {
		if DefaultWafProviders != "" {
			DefaultWafProviders += ", "
		}
		DefaultWafProviders += "citrix-netscaler"
	}
	DefaultCloudProviders = mapKeys(generatedData.Cloud)
}

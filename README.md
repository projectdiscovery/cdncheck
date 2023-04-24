# cdncheck

Helper library that checks if a given IP belongs to known CDN ranges (akamai, cloudflare, incapsula, sucuri and leaseweb).
The library can be used by importing `github.com/projectdiscovery/cdncheck`. here follows a basic example:

```go
package main

import (
	"log"
	"net"
	"github.com/projectdiscovery/cdncheck"
)

func main() {
	client := cdncheck.New()
	if found, _, _, err := client.Check(net.ParseIP("173.245.48.12")); found && err == nil {
		log.Println("ip is part of cdn")
	}
}

```

## Adding new providers

### Static index.yaml

`cmd/generate-index/input.yaml` file contains list of **CDN**, **WAF** and **Cloud** providers. The list contains **URLs**, **ASNs** and **CIDRs** which are then compiled into a final `cidr_data.go` file using `generate-index` program.

Example CDN input.yaml file - 

```yaml
cdn:
  # asn contains the ASN numbers for providers
  asn:
    leaseweb:
      - AS60626

  # urls contains a list of URLs for CDN providers
  urls:
    cloudfront:
      - https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips
    fastly:
      - https://api.fastly.com/public-ip-list

  # cidr contains the CIDR ranges for providers
  cidr:
    akamai:
      - "23.235.32.0/20"
      - "43.249.72.0/22"
      - "103.244.50.0/24"
      - "103.245.222.0/23"
      - "103.245.224.0/24"
      - "104.156.80.0/20"
```

New providers which can be scraped from a URL, ASN or a list of static CIDR can be added to `input.yaml` file.

### Other providers

**CNAME** and **Wappalyzer** based additions can be done in `other.go` file. Just simply add the values to the variables and you're good to go.

```go
// cdnCnameDomains contains a map of CNAME to domains to cdns
var cdnCnameDomains = map[string]string{
	"cloudfront.net":         "amazon",
	"amazonaws.com":          "amazon",
    ...
}

// cdnWappalyzerTechnologies contains a map of wappalyzer technologies to cdns
var cdnWappalyzerTechnologies = map[string]string{
	"imperva":    "imperva",
	"incapsula":  "incapsula",
	...
}
```
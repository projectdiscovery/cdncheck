package generate

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseAWSServiceCIDRs(t *testing.T) {
	body := `{
  "prefixes": [
    {"ip_prefix": "3.168.0.0/14", "region": "GLOBAL", "service": "AMAZON"},
    {"ip_prefix": "3.168.0.0/14", "region": "GLOBAL", "service": "CLOUDFRONT"},
    {"ip_prefix": "52.95.0.0/16", "region": "us-east-1", "service": "EC2"}
  ],
  "ipv6_prefixes": [
    {"ipv6_prefix": "2600:9000:2000::/36", "region": "GLOBAL", "service": "AMAZON"},
    {"ipv6_prefix": "2600:9000:2000::/36", "region": "GLOBAL", "service": "CLOUDFRONT"},
    {"ipv6_prefix": "2600:1f00::/24", "region": "us-east-1", "service": "EC2"}
  ]
}`
	got, err := parseAWSServiceCIDRs(strings.NewReader(body), "CLOUDFRONT")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"3.168.0.0/14", "2600:9000:2000::/36"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseAWSServiceCIDRs() = %v, want %v", got, want)
	}

	if _, err := parseAWSServiceCIDRs(strings.NewReader(`{"prefixes":[]}`), "CLOUDFRONT"); err != errNoCidrFound {
		t.Fatalf("expected errNoCidrFound, got %v", err)
	}
}

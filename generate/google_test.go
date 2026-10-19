package generate

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/projectdiscovery/cdncheck"
)

func TestSubtractCIDRs(t *testing.T) {
	tests := []struct {
		name   string
		from   []string
		remove []string
		want   []string
	}{
		{
			name:   "removes a nested range",
			from:   []string{"10.0.0.0/22"},
			remove: []string{"10.0.1.0/24"},
			want:   []string{"10.0.0.0/24", "10.0.2.0/23"},
		},
		{
			name:   "drops a fully covered range",
			from:   []string{"10.0.0.0/24", "10.1.0.0/24"},
			remove: []string{"10.0.0.0/16"},
			want:   []string{"10.1.0.0/24"},
		},
		{
			name:   "subtracts each ip family separately",
			from:   []string{"10.0.0.0/23", "2001:db8::/31"},
			remove: []string{"10.0.1.0/24", "2001:db9::/32"},
			want:   []string{"10.0.0.0/24", "2001:db8::/32"},
		},
		{
			name:   "keeps ranges that do not overlap",
			from:   []string{"10.0.0.0/24"},
			remove: []string{"192.0.2.0/24"},
			want:   []string{"10.0.0.0/24"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := subtractCIDRs(tt.from, tt.remove)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("subtractCIDRs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExcludeGoogleCloudFromCDN(t *testing.T) {
	compiled := &cdncheck.InputCompiled{
		// goog.json lists Google's whole space; cloud.json carves out GCP customer ranges.
		CDN: map[string][]string{
			"google":     {"8.228.0.0/14", "142.250.0.0/15"},
			"arvancloud": {"185.143.232.0/22"},
		},
		Cloud: map[string][]string{
			"google":     {"8.229.0.0/16"},
			"arvancloud": {"185.143.232.0/22"},
		},
	}
	if err := excludeGoogleCloudFromCDN(compiled); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	google := compiled.CDN["google"]
	for address, wantCDN := range map[string]bool{
		"8.229.57.150":  false, // Compute Engine VM in a cloud.json range
		"8.228.1.1":     true,  // goog.json space outside cloud.json
		"142.250.80.46": true,  // Google front end
	} {
		if got := containsAddress(t, google, address); got != wantCDN {
			t.Errorf("google cdn contains %s = %v, want %v", address, got, wantCDN)
		}
	}
	if !reflect.DeepEqual(compiled.CDN["arvancloud"], []string{"185.143.232.0/22"}) {
		t.Errorf("other providers must stay unchanged, got arvancloud cdn %v", compiled.CDN["arvancloud"])
	}
}

func TestExcludeGoogleCloudFromCDN_KeepsCDNWhenCloudIsMissing(t *testing.T) {
	compiled := &cdncheck.InputCompiled{
		CDN:   map[string][]string{"google": {"8.228.0.0/14"}},
		Cloud: map[string][]string{},
	}
	if err := excludeGoogleCloudFromCDN(compiled); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(compiled.CDN["google"], []string{"8.228.0.0/14"}) {
		t.Fatalf("google cdn = %v, want it unchanged when cloud.json is unavailable", compiled.CDN["google"])
	}
}

func containsAddress(t *testing.T, cidrs []string, address string) bool {
	t.Helper()
	ip := netip.MustParseAddr(address)
	for _, cidr := range cidrs {
		if netip.MustParsePrefix(cidr).Contains(ip) {
			return true
		}
	}
	return false
}

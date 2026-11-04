package cdncheck

import (
	"testing"

	"github.com/projectdiscovery/retryabledns"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/stretchr/testify/require"

	"github.com/miekg/dns"
)

func TestCheckSuffix(t *testing.T) {
	client := New()

	valid, provider, _, err := client.CheckSuffix("test.cloudfront.net")
	require.Nil(t, err, "could not check cname")
	require.True(t, valid, "could not get valid cname")
	require.Equal(t, "amazon", provider, "could not get correct provider")

	valid, provider, _, err = client.CheckSuffix("app.f5edge.com")
	require.Nil(t, err, "could not check f5 suffix")
	require.True(t, valid, "could not get valid f5 suffix")
	require.Equal(t, "f5", provider, "could not get correct provider")

	valid, provider, _, err = client.CheckSuffix("app.volterra.io")
	require.Nil(t, err, "could not check volterra suffix")
	require.True(t, valid, "could not get valid volterra suffix")
	require.Equal(t, "f5", provider, "could not get correct provider")

	valid, _, _, err = client.CheckSuffix("test.provider.net")
	require.Nil(t, err, "could not check cname")
	require.False(t, valid, "could get valid cname")

	// Nested public suffixes and multi-label known suffixes (fixes #544)
	testCases := []struct {
		fqdn     string
		provider string
	}{
		{"dualstack.example.map.fastly.net", "fastly"},
		{"my-lb-123.us-east-1.elb.amazonaws.com", "amazon"},
		{"example.cname.365cyd.cn", "jiasule"},
		{"example.vip.jiasule.org", "jiasule"},
	}

	for _, tc := range testCases {
		matched, prov, itemType, err := client.CheckSuffix(tc.fqdn)
		require.NoError(t, err, "failed checking suffix for %s", tc.fqdn)
		require.True(t, matched, "expected %s to match provider %s", tc.fqdn, tc.provider)
		require.Equal(t, tc.provider, prov, "wrong provider for %s", tc.fqdn)
		require.Equal(t, "waf", itemType)
	}
}

func TestCheckWappalyzer(t *testing.T) {
	client := New()

	valid, provider, err := client.CheckWappalyzer(map[string]struct{}{"imperva": {}})
	require.Nil(t, err, "could not check wappalyzer")
	require.True(t, valid, "could not get valid cname")
	require.Equal(t, "imperva", provider, "could not get correct provider")

	valid, provider, err = client.CheckWappalyzer(map[string]struct{}{"imperva:4.5.6": {}})
	require.Nil(t, err, "could not check wappalyzer")
	require.True(t, valid, "could not get valid cname")
	require.Equal(t, "imperva", provider, "could not get correct provider")

	valid, provider, err = client.CheckWappalyzer(map[string]struct{}{"fastly": {}})
	require.Nil(t, err, "could not check wappalyzer")
	require.True(t, valid, "could not get valid cname")
	require.Equal(t, "fastly", provider, "could not get correct provider")

	valid, provider, err = client.CheckWappalyzer(map[string]struct{}{"sucuri": {}})
	require.Nil(t, err, "could not check wappalyzer")
	require.True(t, valid, "could not get valid cname")
	require.Equal(t, "sucuri", provider, "could not get correct provider")

	valid, provider, err = client.CheckWappalyzer(map[string]struct{}{"f5 distributed cloud": {}})
	require.Nil(t, err)
	require.True(t, valid)
	require.Equal(t, "f5", provider)

	valid, provider, err = client.CheckWappalyzer(map[string]struct{}{"f5 big-ip application security manager": {}})
	require.Nil(t, err)
	require.True(t, valid)
	require.Equal(t, "f5", provider)

	valid, _, err = client.CheckWappalyzer(map[string]struct{}{"azure": {}})
	require.Nil(t, err)
	require.False(t, valid)

	valid, _, err = client.CheckWappalyzer(map[string]struct{}{"google cloud": {}})
	require.Nil(t, err)
	require.False(t, valid)

	valid, _, err = client.CheckWappalyzer(map[string]struct{}{"php": {}})
	require.Nil(t, err, "could not check cname")
	require.False(t, valid, "could get valid cname")
}

func TestCheckDomainWithFallback(t *testing.T) {
	client := New()

	valid, provider, itemType, err := client.CheckDomainWithFallback("www.gap.com")
	// skip if ipv6 not enabled
	if isIPv6Error(err) {
		t.Skip("ipv6 not enabled")
		return
	}
	require.Nil(t, err, "could not check: %v", err)
	require.True(t, valid, "could not check domain")
	require.Equal(t, "akamai", provider, "could not get correct provider")
	require.Equal(t, "waf", itemType, "could not get correct itemType")
}

func isIPv6Error(err error) bool {
	return err != nil && stringsutil.ContainsAnyI(err.Error(), "no route to host", "network is unreachable", "socket operation was attempted to an unreachable network")
}

func TestCheckDNSResponseIPv6(t *testing.T) {
	client := New()
	defaultResolvers := []string{
		"[2001:4860:4860::8888]:53",
		"[2001:4860:4860::8800]:53",

		"8.8.8.8",
		"8.8.0.0",
	}
	defaultMaxRetries := 3

	retryabledns, _ := retryabledns.New(defaultResolvers, defaultMaxRetries)

	dnsData, _ := retryabledns.QueryMultiple("hackerone.com", []uint16{dns.TypeAAAA})

	valid, provider, itemType, err := client.CheckDNSResponse(dnsData)

	require.Nil(t, err, "could not check cname: %v", err)
	require.True(t, valid, "could not get valid cname")
	require.Equal(t, "cloudflare", provider, "could not get correct provider")
	require.Equal(t, "waf", itemType, "could not get correct itemType")
}

func TestCheckDNSResponseIPv4(t *testing.T) {
	client := New()
	defaultResolvers := []string{
		"[2001:4860:4860::8888]:53",
		"[2001:4860:4860::8800]:53",

		"8.8.8.8",
		"8.8.0.0",
	}
	defaultMaxRetries := 3

	retryabledns, _ := retryabledns.New(defaultResolvers, defaultMaxRetries)

	dnsData, _ := retryabledns.QueryMultiple("hackerone.com", []uint16{dns.TypeA})

	valid, provider, itemType, err := client.CheckDNSResponse(dnsData)

	require.Nil(t, err, "could not check cname: %v", err)
	require.True(t, valid, "could not get valid cname")
	require.Equal(t, "cloudflare", provider, "could not get correct provider")
	require.Equal(t, "waf", itemType, "could not get correct itemType")

	dnsData, err = retryabledns.CNAME("www.gap.com")
	// skip if ipv6 not enabled
	if isIPv6Error(err) {
		t.Skip("ipv6 not enabled")
		return
	}
	valid, provider, itemType, err = client.CheckDNSResponse(dnsData)
	require.Nil(t, err, "could not check: %v", err)
	require.True(t, valid, "could not check domain")
	require.Equal(t, "akamai", provider, "could not get correct provider")
	require.Equal(t, "waf", itemType, "could not get correct itemType")

}

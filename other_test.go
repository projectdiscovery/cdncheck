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

	valid, _, _, err = client.CheckSuffix("test.provider.net")
	require.Nil(t, err, "could not check cname")
	require.False(t, valid, "could get valid cname")
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
	return err != nil && stringsutil.ContainsAnyI(err.Error(), "no route to host", "network is unreachable")
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

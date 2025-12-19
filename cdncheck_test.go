package cdncheck

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCDNCheckValid(t *testing.T) {
	client := New()

	found, provider, itemType, err := client.Check(net.ParseIP("2400:cb00::1"))
	require.Equal(t, "cloudflare", provider, "could not get correct provider")
	require.Equal(t, "waf", itemType, "could not get correct item type")
	require.Nil(t, err, "Could not check ip in ranger")
	require.True(t, found, "Could not check cloudlfare ip blacklist")

	found, provider, itemType, err = client.Check(net.ParseIP("173.245.48.12"))
	require.Equal(t, "cloudflare", provider, "could not get correct provider")
	require.Equal(t, "waf", itemType, "could not get correct item type")
	require.Nil(t, err, "Could not check ip in ranger")
	require.True(t, found, "Could not check cloudlfare ip blacklist")

	found, _, _, err = client.Check(net.ParseIP("::1"))
	require.Nil(t, err, "Could not check ip in ranger")
	require.False(t, found, "Localhost IP found in blacklist")

	found, _, _, err = client.Check(net.ParseIP("127.0.0.1"))
	require.Nil(t, err, "Could not check ip in ranger")
	require.False(t, found, "Localhost IP found in blacklist")
}


func TestConnCheckValid(t *testing.T) {
	require.True(
		t,
		checkDialConnectivity(DefaultResolvers, "udp"),
		"DefaultResolvers is showing no connectivity",
	)


	require.False(
		t,
		checkDialConnectivity([]string{
			"[::]:0",
			"[::]:53",
			"[::]:5",
			"[::]:10",
		}, "tcp"),
		"invalid IPs showing as having connectivity",
	)
}

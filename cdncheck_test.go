package cdncheck

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func allHostportsWithPort(hostports []string, port string) (newIps []string) {
	for _, hostport := range hostports {
		host, _, err := net.SplitHostPort(hostport)
		if err != nil { continue }
		newIps = append(newIps, net.JoinHostPort(host, port))
	}

	return newIps
}

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

	require.True(
		t,
		checkDialConnectivity(allHostportsWithPort(DefaultResolvers, "10000"), "udp"),
		"DefaultResolvers using port 10000 is showing no net.Dial connectivity",
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

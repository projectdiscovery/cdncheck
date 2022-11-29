package cdncheck

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCDNCheckValid(t *testing.T) {
	client := New()

	found, provider, itemType, err := client.Check(net.ParseIP("173.245.48.12"))
	require.Equal(t, "cloudflare", provider, "could not get correct provider")
	require.Equal(t, "waf", itemType, "could not get correct item type")
	require.Nil(t, err, "Could not check ip in ranger")
	require.True(t, found, "Could not check cloudlfare ip blacklist")

	found, _, _, err = client.Check(net.ParseIP("127.0.0.1"))
	require.Nil(t, err, "Could not check ip in ranger")
	require.False(t, found, "Localhost IP found in blacklist")
}

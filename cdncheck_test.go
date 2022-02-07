package cdncheck

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCDNCheck(t *testing.T) {
	client, err := New()
	require.Nil(t, err, "Could not create cdncheck client")

	found, provider, err := client.Check(net.ParseIP("173.245.48.12"))
	require.Equal(t, "cloudflare", provider, "could not get correct provider")
	require.Nil(t, err, "Could not check ip in ranger")
	require.True(t, found, "Could not check cloudlfare ip blacklist")

	found, _, err = client.Check(net.ParseIP("127.0.0.1"))
	require.Nil(t, err, "Could not check ip in ranger")
	require.False(t, found, "Localhost IP found in blacklist")
}

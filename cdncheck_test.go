package cdncheck

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCDNCheck(t *testing.T) {
	client, err := New()
	require.Nil(t, err, "Could not create cdncheck client")

	found, err := client.Check(net.ParseIP("173.245.48.12"))
	require.Nil(t, err, "Could not check ip in ranger")
	require.True(t, found, "Could not check cloudlfare ip blacklist")

	found, err = client.Check(net.ParseIP("127.0.0.1"))
	require.Nil(t, err, "Could not check ip in ranger")
	require.False(t, found, "Localhost IP found in blacklist")
}

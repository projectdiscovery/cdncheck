package cdncheck

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckCNAME(t *testing.T) {
	client := New()

	valid, provider, err := client.CheckCNAME([]string{"test.cloudfront.net"})
	require.Nil(t, err, "could not check cname")
	require.True(t, valid, "could not get valid cname")
	require.Equal(t, "amazon", provider, "could not get correct provider")

	valid, _, err = client.CheckCNAME([]string{"test.provider.net"})
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

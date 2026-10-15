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

	found, provider, itemType, err = client.Check(net.ParseIP("49.229.94.1"))
	require.Nil(t, err, "Could not check ip in ranger")
	require.True(t, found, "could not match huawei cdn cidr")
	require.Equal(t, "huawei", provider, "could not get correct provider")
	require.Equal(t, "cdn", itemType, "could not get correct item type")

	// Aliyun CDN
	found, provider, itemType, err = client.Check(net.ParseIP("1.25.68.1"))
	require.Nil(t, err)
	require.True(t, found, "could not match aliyun cdn cidr")
	require.Equal(t, "阿里云", provider)
	require.Equal(t, "cdn", itemType)

	// Wangsu CDN
	found, provider, itemType, err = client.Check(net.ParseIP("1.71.150.1"))
	require.Nil(t, err)
	require.True(t, found, "could not match wangsu cdn cidr")
	require.Equal(t, "网宿", provider)
	require.Equal(t, "cdn", itemType)

	// Tencent Cloud CDN
	found, provider, itemType, err = client.Check(net.ParseIP("1.56.98.1"))
	require.Nil(t, err)
	require.True(t, found, "could not match tencent cdn cidr")
	require.Equal(t, "腾讯云", provider)
	require.Equal(t, "cdn", itemType)

	// Baidu Cloud CDN
	found, provider, itemType, err = client.Check(net.ParseIP("1.56.80.1"))
	require.Nil(t, err)
	require.True(t, found, "could not match baidu cdn cidr")
	require.Equal(t, "百度云加速", provider)
	require.Equal(t, "cdn", itemType)

	// Baidu Domain Suffix
	found, provider, itemType, err = client.CheckSuffix("www.a.shifen.com")
	require.Nil(t, err)
	require.True(t, found, "could not match baidu shifen domain suffix")
	require.Equal(t, "百度智能云 CDN", provider)
	require.Equal(t, "waf", itemType)
}

func TestCheckGoogleCloudCustomerIPIsCloud(t *testing.T) {
	client := New()

	// A Compute Engine VM in a cloud.json range: Google Cloud, not the google CDN.
	found, provider, itemType, err := client.Check(net.ParseIP("34.67.190.20"))
	require.Nil(t, err, "Could not check ip in ranger")
	require.True(t, found, "could not match google cloud cidr")
	require.Equal(t, "google", provider, "could not get correct provider")
	require.Equal(t, "cloud", itemType, "a google cloud customer ip must not match as cdn")

	// A Google front end outside cloud.json stays in the google CDN.
	found, provider, itemType, err = client.Check(net.ParseIP("142.250.80.46"))
	require.Nil(t, err, "Could not check ip in ranger")
	require.True(t, found, "could not match google cdn cidr")
	require.Equal(t, "google", provider, "could not get correct provider")
	require.Equal(t, "cdn", itemType, "could not get correct item type")
}

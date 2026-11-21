package cdncheck

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestProviderScraperMatchMostSpecific covers ranges that the generated data
// really contains: several providers claim the same address.  Matching used to
// return whichever provider the map handed back first, so the reported name
// changed from run to run and -mcdn/-mcloud filtering dropped hosts at random.
func TestProviderScraperMatchMostSpecific(t *testing.T) {
	ranges := map[string][]string{
		"broad":  {"10.0.0.0/8"},
		"narrow": {"10.1.2.0/24"},
	}

	scraper := newProviderScraper(ranges)
	for i := 0; i < 200; i++ {
		matched, provider, err := scraper.Match(net.ParseIP("10.1.2.3"))
		require.Nil(t, err)
		require.True(t, matched)
		require.Equal(t, "narrow", provider, "the most specific prefix must win")
	}

	// An address that is only covered by the broad range still matches it.
	matched, provider, err := scraper.Match(net.ParseIP("10.9.9.9"))
	require.Nil(t, err)
	require.True(t, matched)
	require.Equal(t, "broad", provider)

	// An address outside every range does not match.
	matched, provider, err = scraper.Match(net.ParseIP("192.0.2.1"))
	require.Nil(t, err)
	require.False(t, matched)
	require.Equal(t, "", provider)
}

// TestProviderScraperMatchTieIsStable checks the tie-break for two providers that
// own the exact same prefix (aliyun and jiasule both list 1.31.128.0/24).
func TestProviderScraperMatchTieIsStable(t *testing.T) {
	ranges := map[string][]string{
		"zzz": {"192.0.2.0/24"},
		"aaa": {"192.0.2.0/24"},
	}

	scraper := newProviderScraper(ranges)
	for i := 0; i < 200; i++ {
		matched, provider, err := scraper.Match(net.ParseIP("192.0.2.7"))
		require.Nil(t, err)
		require.True(t, matched)
		require.Equal(t, "aaa", provider, "ties must be broken deterministically by provider name")
	}
}

// TestProviderScraperMatchRealDataOverlap guards the behaviour against the
// generated data, which contains overlapping providers (office365's
// 13.107.6.152/31 sits inside azure's 13.107.4.0/22).
func TestProviderScraperMatchRealDataOverlap(t *testing.T) {
	client := New()

	matched, provider, itemType, err := client.Check(net.ParseIP("13.107.6.152"))
	require.Nil(t, err)
	require.True(t, matched)
	require.Equal(t, "office365", provider, "the /31 must win over the enclosing /22")
	require.Equal(t, "cloud", itemType)

	matched, provider, itemType, err = client.Check(net.ParseIP("14.0.41.5"))
	require.Nil(t, err)
	require.True(t, matched)
	require.Equal(t, "wangsu", provider, "the /24 must win over the enclosing /19")
	require.Equal(t, "cdn", itemType)

	// aliyun and jiasule both list 1.31.128.0/24; the tie is broken by name.
	matched, provider, itemType, err = client.Check(net.ParseIP("1.31.128.5"))
	require.Nil(t, err)
	require.True(t, matched)
	require.Equal(t, "aliyun", provider)
	require.Equal(t, "cdn", itemType)
}

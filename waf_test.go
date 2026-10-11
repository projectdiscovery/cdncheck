package cdncheck

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCitrixNetScalerWAFDetector(t *testing.T) {
	client := New()
	detector := NewWAFDetector()

	// 1. Cookie-based detection: ns_af
	t.Run("Cookie ns_af", func(t *testing.T) {
		headers := map[string][]string{
			"Set-Cookie": {"ns_af=123456789; Path=/; HttpOnly; Secure"},
		}
		matched, provider := detector.MatchHeaders(headers)
		require.True(t, matched)
		require.Equal(t, "citrix-netscaler", provider)

		clientMatched, clientProvider, err := client.CheckWAFHeaders(headers)
		require.NoError(t, err)
		require.True(t, clientMatched)
		require.Equal(t, "citrix-netscaler", clientProvider)

		genMatched, genProvider, genType, err := client.CheckHeaders(headers)
		require.NoError(t, err)
		require.True(t, genMatched)
		require.Equal(t, "citrix-netscaler", genProvider)
		require.Equal(t, "waf", genType)
	})

	// 2. Cookie-based detection: citrix_ns_id
	t.Run("Cookie citrix_ns_id", func(t *testing.T) {
		headers := map[string][]string{
			"Set-Cookie": {"citrix_ns_id=abcdef123456; domain=.example.com; path=/"},
		}
		matched, provider := detector.MatchHeaders(headers)
		require.True(t, matched)
		require.Equal(t, "citrix-netscaler", provider)
	})

	// 3. Cookie-based detection: citrix_ns_id_dis
	t.Run("Cookie citrix_ns_id_dis", func(t *testing.T) {
		headers := map[string][]string{
			"Set-Cookie": {"citrix_ns_id_dis=xyz987; path=/"},
		}
		matched, provider := detector.MatchHeaders(headers)
		require.True(t, matched)
		require.Equal(t, "citrix-netscaler", provider)
	})

	// 4. Cookie-based detection: NSC_ prefix
	t.Run("Cookie NSC_ prefix", func(t *testing.T) {
		testCases := []string{
			"NSC_af_appfw=12345",
			"NSC_PERSIST_VIP=98765",
			"NSC_esns=abcdef",
			"nsc_tm_session=active",
		}
		for _, cookie := range testCases {
			headers := map[string][]string{
				"Set-Cookie": {cookie + "; path=/"},
			}
			matched, provider := detector.MatchHeaders(headers)
			require.True(t, matched, "expected match for cookie %s", cookie)
			require.Equal(t, "citrix-netscaler", provider)
		}
	})

	// 5. Cookie-based detection: pwcount
	t.Run("Cookie pwcount", func(t *testing.T) {
		headers := map[string][]string{
			"Set-Cookie": {"pwcount=1; path=/"},
		}
		matched, provider := detector.MatchHeaders(headers)
		require.True(t, matched)
		require.Equal(t, "citrix-netscaler", provider)
	})

	// 6. Direct MatchCookies method
	t.Run("MatchCookies direct", func(t *testing.T) {
		matched, provider := detector.MatchCookies("ns_af")
		require.True(t, matched)
		require.Equal(t, "citrix-netscaler", provider)

		matched, provider = detector.MatchCookies("citrix_ns_id")
		require.True(t, matched)
		require.Equal(t, "citrix-netscaler", provider)

		matched, provider = detector.MatchCookies("NSC_test_persistence")
		require.True(t, matched)
		require.Equal(t, "citrix-netscaler", provider)
	})

	// 7. Header-based detection: Via: NS-CACHE
	t.Run("Header Via NS-CACHE", func(t *testing.T) {
		testHeaders := []map[string][]string{
			{"Via": {"NS-CACHE-8.0: 123"}},
			{"via": {"1.1 NS-CACHE"}},
			{"VIA": {"NS-CACHE-9.0"}},
		}
		for _, h := range testHeaders {
			matched, provider := detector.MatchHeaders(h)
			require.True(t, matched)
			require.Equal(t, "citrix-netscaler", provider)
		}
	})

	// 8. Header key obfuscation: Cneonction and nnCoection
	t.Run("Obfuscated Connection Header", func(t *testing.T) {
		headers1 := map[string][]string{
			"Cneonction": {"close"},
		}
		matched, provider := detector.MatchHeaders(headers1)
		require.True(t, matched)
		require.Equal(t, "citrix-netscaler", provider)

		headers2 := map[string][]string{
			"nnCoection": {"close"},
		}
		matched, provider = detector.MatchHeaders(headers2)
		require.True(t, matched)
		require.Equal(t, "citrix-netscaler", provider)
	})

	// 9. Citrix-specific headers: X-Citrix-Application and X-Citrix-Gateway
	t.Run("Citrix Headers", func(t *testing.T) {
		headers1 := map[string][]string{
			"X-Citrix-Application": {"AppFirewall"},
		}
		matched, provider := detector.MatchHeaders(headers1)
		require.True(t, matched)
		require.Equal(t, "citrix-netscaler", provider)

		headers2 := map[string][]string{
			"X-Citrix-Gateway": {"1"},
		}
		matched, provider = detector.MatchHeaders(headers2)
		require.True(t, matched)
		require.Equal(t, "citrix-netscaler", provider)
	})

	// 10. MatchHeaderMap (single-valued map)
	t.Run("MatchHeaderMap", func(t *testing.T) {
		headerMap := map[string]string{
			"Via": "NS-CACHE-8.0",
		}
		matched, provider := detector.MatchHeaderMap(headerMap)
		require.True(t, matched)
		require.Equal(t, "citrix-netscaler", provider)
	})

	// 11. Body-based detection (error and block pages)
	t.Run("Body signatures", func(t *testing.T) {
		bodies := [][]byte{
			[]byte("<html><body>Error: NS_APPFW_SESSION_ID=12345 blocked</body></html>"),
			[]byte("<html><body>Reference: NS_TRANSACTION_ID: 987654</body></html>"),
			[]byte("<html><title>Citrix NetScaler - Access Denied</title></html>"),
			[]byte("NetScaler AppFirewall policy violation"),
		}
		for _, b := range bodies {
			matched, provider := detector.MatchBody(b)
			require.True(t, matched, "expected match for body: %s", string(b))
			require.Equal(t, "citrix-netscaler", provider)

			cMatched, cProvider, err := client.CheckWAFResponse(nil, b)
			require.NoError(t, err)
			require.True(t, cMatched)
			require.Equal(t, "citrix-netscaler", cProvider)
		}
	})

	// 12. Negative tests: benign responses should not trigger WAF detection
	t.Run("Benign responses", func(t *testing.T) {
		benignHeaders := map[string][]string{
			"Server":          {"Apache/2.4.41 (Ubuntu)"},
			"Content-Type":    {"text/html; charset=UTF-8"},
			"Set-Cookie":      {"session_id=abc123xyz; Path=/; HttpOnly", "theme=dark; Path=/"},
			"Via":             {"1.1 varnish"},
			"X-Frame-Options": {"SAMEORIGIN"},
		}
		matched, provider := detector.MatchHeaders(benignHeaders)
		require.False(t, matched)
		require.Empty(t, provider)

		clientMatched, clientProvider, err := client.CheckWAFHeaders(benignHeaders)
		require.NoError(t, err)
		require.False(t, clientMatched)
		require.Empty(t, clientProvider)

		benignBody := []byte("<html><body>Welcome to our website!</body></html>")
		matched, provider = detector.Match(benignHeaders, benignBody)
		require.False(t, matched)
		require.Empty(t, provider)
	})
}

func TestCheckWappalyzerCitrixNetScaler(t *testing.T) {
	client := New()

	testCases := []string{
		"citrix netscaler",
		"citrix netscaler:13.1",
		"citrix adc",
		"citrix adc:13.0",
		"citrix",
		"netscaler",
	}

	for _, tc := range testCases {
		valid, provider, err := client.CheckWappalyzer(map[string]struct{}{tc: {}})
		require.NoError(t, err)
		require.True(t, valid, "expected match for %s", tc)
		require.Equal(t, "citrix-netscaler", provider)
	}
}

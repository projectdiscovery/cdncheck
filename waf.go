package cdncheck

import (
	"bytes"
	"regexp"
	"strings"
)

// WAFFingerprint defines fingerprint signatures for a WAF provider.
type WAFFingerprint struct {
	Name       string            `json:"name" yaml:"name"`
	Headers    map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	HeaderKeys []string          `json:"header_keys,omitempty" yaml:"header_keys,omitempty"`
	Cookies    []string          `json:"cookies,omitempty" yaml:"cookies,omitempty"`
	Body       []string          `json:"body,omitempty" yaml:"body,omitempty"`
}

// DefaultWAFFingerprints contains detection signatures for known WAF providers.
var DefaultWAFFingerprints = []WAFFingerprint{
	{
		Name: "citrix-netscaler",
		Headers: map[string]string{
			"via":                   "ns-cache",
			"x-citrix-application": "",
			"x-citrix-gateway":     "",
		},
		HeaderKeys: []string{
			"cneonction",
			"nncoection",
			"x-citrix-application",
			"x-citrix-gateway",
		},
		Cookies: []string{
			"ns_af",
			"citrix_ns_id",
			"citrix_ns_id_dis",
			"nsc_",
			"pwcount",
		},
		Body: []string{
			"ns_appfw_session_id",
			"ns_transaction_id",
			"citrix netscaler",
			"netscaler appfirewall",
		},
	},
	{
		Name: "cloudflare",
		Headers: map[string]string{
			"server": "cloudflare",
			"cf-ray": "",
		},
		HeaderKeys: []string{
			"cf-ray",
			"cf-cache-status",
		},
		Cookies: []string{
			"__cfduid",
			"__cf_bm",
		},
	},
	{
		Name: "incapsula",
		Headers: map[string]string{
			"x-cdn":   "incapsula",
			"x-iinfo": "",
		},
		HeaderKeys: []string{
			"x-iinfo",
		},
		Cookies: []string{
			"visid_incap",
			"incap_ses",
		},
	},
	{
		Name: "akamai",
		Headers: map[string]string{
			"server":               "akamaighost",
			"x-akamai-transformed": "",
		},
		Cookies: []string{
			"ak_bmsc",
		},
	},
	{
		Name: "aws",
		Headers: map[string]string{
			"x-amzn-waf-action": "",
		},
		HeaderKeys: []string{
			"x-amzn-waf-action",
		},
		Cookies: []string{
			"aws-waf-token",
		},
	},
	{
		Name: "f5-bigip",
		Cookies: []string{
			"bigipserver",
			"ts01",
		},
	},
	{
		Name: "sucuri",
		Headers: map[string]string{
			"x-sucuri-id":    "",
			"x-sucuri-cache": "",
		},
		HeaderKeys: []string{
			"x-sucuri-id",
			"x-sucuri-cache",
		},
	},
	{
		Name: "modsecurity",
		Headers: map[string]string{
			"server": "mod_security",
		},
	},
}

// compiledRule caches compiled patterns for a fingerprint rule.
type compiledRule struct {
	fingerprint WAFFingerprint
	bodyRegexes []*regexp.Regexp
}

// WAFDetector inspects HTTP response artifacts against WAF fingerprint signatures.
type WAFDetector struct {
	rules []compiledRule
}

// NewWAFDetector constructs a WAF detector with default fingerprint signatures.
func NewWAFDetector() *WAFDetector {
	return NewWAFDetectorWithRules(DefaultWAFFingerprints)
}

// NewWAFDetectorWithRules constructs a WAF detector with custom fingerprint rules.
func NewWAFDetectorWithRules(fingerprints []WAFFingerprint) *WAFDetector {
	rules := make([]compiledRule, 0, len(fingerprints))
	for _, fp := range fingerprints {
		cr := compiledRule{fingerprint: fp}
		for _, b := range fp.Body {
			if strings.Contains(b, "|") {
				if re, err := regexp.Compile("(?i)" + b); err == nil {
					cr.bodyRegexes = append(cr.bodyRegexes, re)
				}
			}
		}
		rules = append(rules, cr)
	}
	return &WAFDetector{rules: rules}
}

// Providers returns all provider names recognized by the detector.
func (w *WAFDetector) Providers() []string {
	names := make([]string, 0, len(w.rules))
	for _, r := range w.rules {
		names = append(names, r.fingerprint.Name)
	}
	return names
}

// Match inspects both HTTP headers and response body for WAF signatures.
func (w *WAFDetector) Match(headers map[string][]string, body []byte) (bool, string) {
	if matched, provider := w.MatchHeaders(headers); matched {
		return true, provider
	}
	if len(body) > 0 {
		return w.MatchBody(body)
	}
	return false, ""
}

// MatchHeaders inspects HTTP response headers (including cookies) for WAF signatures.
func (w *WAFDetector) MatchHeaders(headers map[string][]string) (bool, string) {
	if len(headers) == 0 {
		return false, ""
	}

	normalizedHeaders := make(map[string][]string, len(headers))
	var cookies []string

	for k, vals := range headers {
		lowerK := strings.ToLower(strings.TrimSpace(k))
		normalizedHeaders[lowerK] = vals

		if lowerK == "set-cookie" || lowerK == "cookie" {
			for _, v := range vals {
				cookies = append(cookies, extractCookieNames(v)...)
			}
		}
	}

	for _, rule := range w.rules {
		fp := rule.fingerprint

		// Check header presence and value patterns
		for hk, expectedSubstr := range fp.Headers {
			vals, exists := normalizedHeaders[strings.ToLower(hk)]
			if !exists {
				continue
			}
			if expectedSubstr == "" {
				return true, fp.Name
			}
			for _, v := range vals {
				if strings.Contains(strings.ToLower(v), strings.ToLower(expectedSubstr)) {
					return true, fp.Name
				}
			}
		}

		// Check specific header key existence
		for _, hk := range fp.HeaderKeys {
			if _, exists := normalizedHeaders[strings.ToLower(hk)]; exists {
				return true, fp.Name
			}
		}

		// Check cookies
		for _, cookieName := range cookies {
			lowerCookie := strings.ToLower(cookieName)
			for _, target := range fp.Cookies {
				targetLower := strings.ToLower(target)
				if lowerCookie == targetLower || strings.HasPrefix(lowerCookie, targetLower) {
					return true, fp.Name
				}
			}
		}
	}

	return false, ""
}

// MatchHeaderMap inspects single-valued header map for WAF signatures.
func (w *WAFDetector) MatchHeaderMap(headers map[string]string) (bool, string) {
	multi := make(map[string][]string, len(headers))
	for k, v := range headers {
		multi[k] = []string{v}
	}
	return w.MatchHeaders(multi)
}

// MatchCookies inspects cookie names against WAF signatures.
func (w *WAFDetector) MatchCookies(cookies ...string) (bool, string) {
	for _, rule := range w.rules {
		for _, c := range cookies {
			lowerC := strings.ToLower(strings.TrimSpace(c))
			for _, target := range rule.fingerprint.Cookies {
				targetLower := strings.ToLower(target)
				if lowerC == targetLower || strings.HasPrefix(lowerC, targetLower) {
					return true, rule.fingerprint.Name
				}
			}
		}
	}
	return false, ""
}

// MatchBody inspects response body content for WAF signatures.
func (w *WAFDetector) MatchBody(body []byte) (bool, string) {
	lowerBody := bytes.ToLower(body)
	for _, rule := range w.rules {
		for _, pattern := range rule.fingerprint.Body {
			if bytes.Contains(lowerBody, []byte(strings.ToLower(pattern))) {
				return true, rule.fingerprint.Name
			}
		}
		for _, re := range rule.bodyRegexes {
			if re.Match(body) {
				return true, rule.fingerprint.Name
			}
		}
	}
	return false, ""
}

// MatchString inspects single-valued headers and string body.
func (w *WAFDetector) MatchString(headers map[string]string, body string) (bool, string) {
	if matched, provider := w.MatchHeaderMap(headers); matched {
		return true, provider
	}
	if body != "" {
		return w.MatchBody([]byte(body))
	}
	return false, ""
}

// extractCookieNames extracts individual cookie names from a Set-Cookie or Cookie header value.
func extractCookieNames(headerVal string) []string {
	var names []string
	parts := strings.Split(headerVal, ";")
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		if eqIdx := strings.Index(trimmed, "="); eqIdx > 0 {
			name := strings.TrimSpace(trimmed[:eqIdx])
			names = append(names, name)
		} else {
			names = append(names, trimmed)
		}
	}
	return names
}

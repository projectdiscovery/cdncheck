package testutils

import (
	"strings"

	errorutils "github.com/projectdiscovery/utils/errors"
)

type TestCase struct {
	Target      string
	Args        string
	Expected    []string
	CompareFunc func(target string, got []string) error
}

var TestCases = []TestCase{
	{Target: "52.60.165.183", Expected: []string{"[INF] Found result: 1 (CLOUD: 1)"}, Args: "-nc"},
	{Target: "projectdiscovery.io", Expected: []string{"[INF] Found result: 1 (WAF: 1)"}, Args: "-nc"},
	{Target: "gslink.hackerone.com", Expected: []string{"[INF] Found result: 1 (CDN: 1)"}, Args: "-nc"},
	{Target: "52.60.165.183", Expected: []string{"52.60.165.183 [cloud] [aws]", "[INF] Found result: 1 (CLOUD: 1)"}, Args: "-resp -nc"},
	{Target: "52.60.165.183", Expected: []string{"52.60.165.183 [cloud] [aws]", "[INF] Found result: 1 (CLOUD: 1)"}, Args: "-resp -cloud -nc"},
	{Target: "104.16.51.111", Expected: []string{"104.16.51.111 [waf] [cloudflare]", "[INF] Found result: 1 (WAF: 1)"}, Args: "-resp -waf -nc"},
	{Target: "54.192.171.16", Expected: []string{"54.192.171.16 [cdn] [cloudfront]", "[INF] Found result: 1 (CDN: 1)"}, Args: "-resp -cdn -nc"},
	{Target: "185.199.109.153", Expected: []string{"[INF] No results found."}, Args: "-nc"},
	{Target: "185.199.109.153", Expected: []string{"[INF] No results found."}, Args: "-resp -nc"},
	{Target: "54.192.171.16", Expected: []string{"54.192.171.16 [cdn] [cloudfront]", "[INF] Found result: 1 (CDN: 1)"}, Args: "-resp -mcdn cloudfront -nc"},
	{Target: "54.192.171.16", Expected: []string{"[INF] No results found."}, Args: "-resp -fcdn cloudfront -mcloud aws -nc"},
	{Target: "projectdiscovery.io", Expected: nil, Args: "-resp -nc", CompareFunc: func(target string, got []string) error {
		cdn := "cloudflare"
		if len(got) == 2 && strings.Contains(got[0], cdn) {
			return nil
		}
		return errorutils.New("expected %v belong to %v cdn but got: %v", target, cdn, got)
	}},
}

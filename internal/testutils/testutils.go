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
	{Target: "52.60.165.183", Expected: []string{"52.60.165.183"}, Args: "-nc"},
	{Target: "projectdiscovery.io", Expected: []string{"projectdiscovery.io"}, Args: "-nc"},
	{Target: "gslink.hackerone.com", Expected: []string{"gslink.hackerone.com"}, Args: "-nc"},
	{Target: "52.60.165.183", Expected: []string{"52.60.165.183 [cloud] [aws]"}, Args: "-resp -nc"},
	{Target: "52.60.165.183", Expected: []string{"52.60.165.183 [cloud] [aws]"}, Args: "-resp -cloud -nc"},
	{Target: "104.16.51.111", Expected: []string{"104.16.51.111 [waf] [cloudflare]"}, Args: "-resp -waf -nc"},
	{Target: "54.192.171.16", Expected: []string{"54.192.171.16 [cdn] [cloudfront]"}, Args: "-resp -cdn -nc"},
	{Target: "185.199.109.153", Expected: []string{}, Args: "-nc"},
	{Target: "185.199.109.153", Expected: []string{}, Args: "-resp -nc"},
	{Target: "54.192.171.16", Expected: []string{"54.192.171.16 [cdn] [cloudfront]"}, Args: "-resp -mcdn cloudfront -nc"},
	{Target: "54.192.171.16", Expected: []string{}, Args: "-resp -fcdn cloudfront -mcloud aws -nc"},
	{Target: "projectdiscovery.io", Expected: nil, Args: "-resp -nc", CompareFunc: func(target string, got []string) error {
		cdn := "cloudflare"
		if len(got) == 1 && strings.Contains(got[0], cdn) {
			return nil
		}
		return errorutils.New("expected %v belong to %v cdn but got: %v", target, cdn, got)
	}},
}

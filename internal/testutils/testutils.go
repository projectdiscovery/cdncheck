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
	{Target: "52.60.165.183", Expected: []string{"52.60.165.183"}},
	{Target: "52.60.165.183", Expected: []string{"52.60.165.183 [cloud] [aws]"}, Args: "-resp"},
	{Target: "52.60.165.183", Expected: []string{"52.60.165.183 [cloud] [aws]"}, Args: "-resp -cloud"},
	{Target: "104.16.51.111", Expected: []string{"104.16.51.111 [waf] [cloudflare]"}, Args: "-resp -waf"},
	{Target: "54.192.171.16", Expected: []string{"54.192.171.16 [cdn] [cloudfront]"}, Args: "-resp -cdn"},
	{Target: "185.199.109.153", Expected: []string{"185.199.109.153"}, Args: "-e"},
	{Target: "185.199.109.153", Expected: []string{"185.199.109.153"}, Args: "-resp -e"},
	{Target: "54.192.171.16", Expected: []string{"54.192.171.16 [cdn] [cloudfront]"}, Args: "-resp -mcdn cloudfront"},
	{Target: "54.192.171.16", Expected: []string{}, Args: "-resp -fcdn cloudfront -mcloud aws"},
	{Target: "projectdiscovery.io", Expected: nil, Args: "-resp", CompareFunc: func(target string, got []string) error {
		cdn := "cloudflare"
		if len(got) == 1 && strings.Contains(got[0], cdn) {
			return nil
		}
		return errorutils.New("expected %v belong to %v cdn but got: %v", target, cdn, got)
	}},
	{Target: "2a04:4e42:ff1::169:a86d", Expected: []string{"2a04:4e42:ff1::169:a86d [cdn] [fastly]"}, Args: "-resp"},
}

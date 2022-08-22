package testutils

type TestCase struct {
	Target   string
	Args     string
	Expected []string
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
	{Target: "54.192.171.16", Expected: []string{}, Args: "-resp -fcdn cloudfront"},
	{Target: "Filter flags", Expected: []string{}, Args: "-l test-data/list.txt -resp -fcdn cloudfront -fcloud aws -fwaf cloudflare"},
	{Target: "Filter and Match flags", Expected: []string{"54.192.171.16 [cdn] [cloudfront]", "104.16.51.111 [waf] [cloudflare]"}, Args: "-l test-data/list.txt -resp -mcdn cloudfront -mwaf cloudflare -fcloud aws"},
}

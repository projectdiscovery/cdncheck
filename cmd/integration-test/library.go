package main

import (
	"net"

	"github.com/projectdiscovery/cdncheck"
	errorutil "github.com/projectdiscovery/utils/errors"
)

var libraryTestcases = map[string]TestCase{
	"cdncheck as library": &goIntegrationTest{},
}

type goIntegrationTest struct{}

func (h *goIntegrationTest) Execute() error {
	client := cdncheck.New()
	ip := net.ParseIP("173.245.48.12")
	// checks if an IP is contained in the cdn denylist
	matched, val, err := client.CheckCDN(ip)
	if err != nil {
		return err
	}
	if matched {
		return errorutil.New("Expected %v is WAF, but got %v", ip, val)
	}
	// checks if an IP is contained in the cloud denylist
	matched, val, err = client.CheckCloud(ip)
	if err != nil {
		return err
	}
	if matched {
		return errorutil.New("Expected %v is WAF, but got %v", ip, val)
	}
	// checks if an IP is contained in the waf denylist
	matched, val, err = client.CheckWAF(ip)
	if err != nil {
		return err
	}
	if !matched {
		return errorutil.New("Expected %v WAF is cloudflare, but got %v", ip, val)
	}
	return err
}

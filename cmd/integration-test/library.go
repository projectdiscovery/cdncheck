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
	ip := "173.245.48.12"
	found, _, _, err := client.Check(net.ParseIP(ip))
	if !found {
		return errorutil.New("Expected %v is part of cdn", ip)
	}
	return err
}

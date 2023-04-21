package main

import (
	"github.com/projectdiscovery/cdncheck/internal/runner"
	errorutil "github.com/projectdiscovery/utils/errors"
)

var libraryTestcases = map[string]TestCase{
	"cdncheck as library": &goIntegrationTest{},
}

type goIntegrationTest struct{}

func (h *goIntegrationTest) Execute() error {
	results := []runner.Output{}
	options := runner.Options{
		Inputs:   []string{"projectdiscovery.io", "173.245.48.12"},
		Response: true,
		OnResult: func(r runner.Output) {
			results = append(results, r)
		},
	}
	runnner := runner.NewRunner(&options)
	err := runnner.Run()
	for _, result := range results {
		if result.Input == "projectdiscovery.io" && result.WafName != "cloudflare" {
			err = errorutil.New("expected projectdiscovery cdn as cloudflare, got %v", result.CdnName)
		}
	}
	return err
}

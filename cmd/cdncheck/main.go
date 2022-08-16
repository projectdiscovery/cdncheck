package main

import (
	"github.com/projectdiscovery/cdncheck/internal/runner"
	"github.com/projectdiscovery/gologger"
)

func main() {
	options := runner.ParseOptions()

	newRunner := runner.NewRunner(options)

	err := newRunner.Run()
	if err != nil {
		gologger.Fatal().Msgf("Could not run cdncheck enumeration: %s\n", err)
	}
}

// func process() error {
// 	options, err := readFlags()
// 	if err != nil {
// 		return errors.Wrap(err, "could not parse flags")
// 	}
// 	return execute(options, cdncheck.New())
// }
// Parse the command line flags and read config files

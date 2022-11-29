package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/cdncheck/internal/testutils"
)

var (
	debug             = os.Getenv("DEBUG") == "true"
	success           = aurora.Green("[✓]").String()
	failed            = aurora.Red("[✘]").String()
	errored           = false
	devCdncheckBinary = flag.String("dev", "", "Dev Branch Cdncheck Binary")
)

func main() {
	flag.Parse()
	if err := runFunctionalTests(); err != nil {
		log.Fatalf("Could not run functional tests: %s\n", err)
	}
	if errored {
		os.Exit(1)
	}
}

func runFunctionalTests() error {
	for _, testcase := range testutils.TestCases {
		if err := runIndividualTestCase(testcase.Target, testcase.Args, testcase.Expected); err != nil {
			errored = true
			fmt.Fprintf(os.Stderr, "%s Test \"%s\" failed: %s\n", failed, testcase.Target, err)
		} else {
			fmt.Printf("%s Test \"%s\" passed!\n", success, testcase.Target)
		}
	}
	return nil
}

func runIndividualTestCase(target string, args string, expected []string) error {
	argsParts := strings.Fields(args)
	devOutput, err := testutils.RunCdncheckBinaryAndGetResults(target, *devCdncheckBinary, debug, argsParts)
	if err != nil {
		return errors.Wrap(err, "could not run Cdncheck dev test")
	}
	if !testutils.CompareOutput(devOutput, expected) {
		return errors.Errorf("expected output %s, got %s", expected, devOutput)
	}
	return nil
}

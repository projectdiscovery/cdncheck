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
		if err := runIndividualTestCase(testcase); err != nil {
			errored = true
			fmt.Fprintf(os.Stderr, "%s Test \"%s\" failed: %s\n", failed, testcase.Target, err)
		} else {
			fmt.Printf("%s Test \"%s\" passed!\n", success, testcase.Target)
		}
	}
	return nil
}

func runIndividualTestCase(testcase testutils.TestCase) error {
	argsParts := strings.Fields(testcase.Args)
	devOutput, err := testutils.RunCdncheckBinaryAndGetResults(testcase.Target, *devCdncheckBinary, debug, argsParts)
	if err != nil {
		return errors.Wrap(err, "could not run Cdncheck dev test")
	}
	if testcase.CompareFunc != nil {
		return testcase.CompareFunc(testcase.Target, devOutput)
	}
	if !testutils.CompareOutput(devOutput, testcase.Expected) {
		return errors.Errorf("expected output %s, got %s", testcase.Expected, devOutput)
	}
	return nil
}

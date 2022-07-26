package main

import (
	"bufio"
	"fmt"
	"net"
	"os"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/mapcidr"
)

func main() {
	if err := process(); err != nil {
		gologger.Fatal().Msgf("Could not process: %s\n", err)
	}
}

func process() error {
	options, err := readFlags()
	if err != nil {
		return errors.Wrap(err, "could not parse flags")
	}
	cdnclient, err := cdncheck.NewWithCache()
	if err != nil {
		return errors.Wrap(err, "could not create cdncheck client")
	}
	return execute(options, cdnclient)
}

func execute(opts *options, cdnclient *cdncheck.Client) error {
	for _, target := range opts.inputs {
		processInputItem(target, opts, cdnclient)
	}
	if opts.list != "" {
		file, err := os.Open(opts.list)
		if err != nil {
			return errors.Wrap(err, "could not open input file")
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			text := scanner.Text()
			if text != "" {
				processInputItem(text, opts, cdnclient)
			}
		}
	}
	if opts.hasStdin {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			text := scanner.Text()
			if text != "" {
				processInputItem(text, opts, cdnclient)
			}
		}
	}
	return nil
}

// processInputItem processes a single input item
func processInputItem(input string, opts *options, cdnclient *cdncheck.Client) {
	// CIDR input
	if _, ipRange, _ := net.ParseCIDR(input); ipRange != nil {
		cidrInputs, err := mapcidr.IPAddressesAsStream(input)
		if err != nil {
			gologger.Error().Msgf("Could not parse cidr %s: %s", input, err)
			return
		}
		for cidr := range cidrInputs {
			processInputItemSingle(cidr, opts, cdnclient)
		}
	} else {
		// Normal input
		processInputItemSingle(input, opts, cdnclient)
	}
}

func processInputItemSingle(item string, opts *options, cdnclient *cdncheck.Client) {
	parsed := net.ParseIP(item)
	if parsed == nil {
		gologger.Error().Msgf("Could not parse IP address: %s", item)
		return
	}
	isCDN, provider, err := cdnclient.Check(parsed)
	if err != nil {
		gologger.Error().Msgf("Could not check IP cdn %s: %s", item, err)
		return
	}
	if !isCDN {
		if !opts.print {
			fmt.Printf("%s\n", item)
		}
	} else if opts.print {
		fmt.Printf("[%s] %s\n", provider, item)
	}
}

type options struct {
	inputs   goflags.StringSlice
	list     string
	print    bool
	hasStdin bool
}

// readFlags reads the flags and options for the utility
func readFlags() (*options, error) {
	opts := &options{}
	opts.hasStdin = fileutil.HasStdin()

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("cdncheck is a utility for ignoring CDN range IPs")
	flagSet.StringSliceVarP(&opts.inputs, "inputs", "i", nil, "inputs to process", goflags.CommaSeparatedStringSliceOptions)
	flagSet.StringVarP(&opts.list, "list", "l", "", "file with inputs to process")
	flagSet.BoolVarP(&opts.print, "print", "p", false, "print CDN ips (default to exclude)")

	return opts, flagSet.Parse()
}

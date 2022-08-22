package runner

import (
	"bufio"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/mapcidr"
)

type Runner struct {
	options   *Options
	cdnclient *cdncheck.Client
}

func NewRunner(options *Options) *Runner {
	return &Runner{
		options:   options,
		cdnclient: cdncheck.New(),
	}
}

func (r *Runner) Run() error {
	writer, err := r.configureOutput()
	if err != nil {
		return errors.Wrap(err, "could not configure output")
	}
	defer writer.Close()
	output := make(chan Output, 1)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go r.process(output, writer, wg)
	wg.Add(1)
	go r.waitForData(output, writer, wg)
	wg.Wait()
	return nil
}
func (r *Runner) process(output chan Output, writer *OutputWriter, wg *sync.WaitGroup) {
	defer wg.Done()
	defer close(output)
	for _, target := range r.options.inputs {
		processInputItem(target, r.options, r.cdnclient, output)
	}
	if r.options.list != "" {
		file, err := os.Open(r.options.list)
		if err != nil {
			gologger.Fatal().Msgf("Could not open input file: %s", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			text := scanner.Text()
			if text != "" {
				processInputItem(text, r.options, r.cdnclient, output)
			}
		}
	}
	if r.options.hasStdin {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			text := scanner.Text()
			if text != "" {
				processInputItem(text, r.options, r.cdnclient, output)
			}
		}
	}
}
func (r *Runner) waitForData(output chan Output, writer *OutputWriter, wg *sync.WaitGroup) {
	defer wg.Done()
	for receivedData := range output {
		if r.options.json {
			if receivedData.itemType != "cdn" {
				receivedData.Cdn = false
				receivedData.CdnName = ""
			}
			writer.WriteJSON(receivedData)
		} else {
			if r.options.response && !r.options.exclude {
				writer.WriteString(receivedData.String())
			} else {
				writer.WriteString(receivedData.StringIP())
			}
		}
	}
}
func (r *Runner) configureOutput() (*OutputWriter, error) {
	outputWriter, err := NewOutputWriter()
	if err != nil {
		return nil, err
	}
	outputWriter.AddWriters(os.Stdout)
	if r.options.output != "" {
		outputFile, err := os.Create(r.options.output)
		if err != nil {
			return nil, err
		}
		outputWriter.AddWriters(outputFile)
	}
	return outputWriter, nil
}

// processInputItem processes a single input item
func processInputItem(input string, options *Options, cdnclient *cdncheck.Client, output chan Output) {
	// CIDR input
	if _, ipRange, _ := net.ParseCIDR(input); ipRange != nil {
		cidrInputs, err := mapcidr.IPAddressesAsStream(input)
		if err != nil {
			gologger.Error().Msgf("Could not parse cidr %s: %s", input, err)
			return
		}
		for cidr := range cidrInputs {
			processInputItemSingle(cidr, options, cdnclient, output)
		}
	} else {
		// Normal input
		processInputItemSingle(input, options, cdnclient, output)
	}
}

func processInputItemSingle(item string, options *Options, cdnclient *cdncheck.Client, output chan Output) {
	parsed := net.ParseIP(item)
	if parsed == nil {
		gologger.Error().Msgf("Could not parse IP address: %s", item)
		return
	}
	isCDN, provider, itemType, err := cdnclient.Check(parsed)
	if err != nil {
		gologger.Error().Msgf("Could not check IP cdn %s: %s", item, err)
		return
	}

	data := Output{
		Timestamp: time.Now(),
		IP:        item,
		Cdn:       isCDN,
		CdnName:   provider,
		itemType:  itemType,
	}
	if options.exclude {
		if !data.Cdn {
			output <- data
		}
		return
	}
	if skipped := filterIP(options, data); skipped {
		return
	}
	if matched := matchIP(options, data); !matched {
		return
	}
	switch {
	case options.cdn && data.itemType == "cdn",
		options.cloud && data.itemType == "cloud",
		options.waf && data.itemType == "waf":
		{
			output <- data
		}
	case (!options.cdn && !options.waf && !options.cloud) && data.Cdn:
		{
			output <- data
		}
	}
}
func matchIP(options *Options, data Output) bool {
	if len(options.matchCdn) == 0 && len(options.matchCloud) == 0 && len(options.matchWaf) == 0 {
		return true
	}
	if len(options.matchCdn) > 0 && data.itemType == "cdn" {
		matched := false
		for _, filter := range options.matchCdn {
			if filter == data.CdnName {
				matched = true
			}
		}
		if matched {
			return true
		}
	}
	if len(options.matchCloud) > 0 && data.itemType == "cloud" {
		matched := false
		for _, filter := range options.matchCloud {
			if filter == data.CdnName {
				matched = true
			}
		}
		if matched {
			return true
		}
	}
	if len(options.matchWaf) > 0 && data.itemType == "waf" {
		matched := false
		for _, filter := range options.matchWaf {
			if filter == data.CdnName {
				matched = true
			}
		}
		if matched {
			return true
		}
	}
	return false
}
func filterIP(options *Options, data Output) bool {
	if len(options.filterCdn) == 0 && len(options.filterCloud) == 0 && len(options.filterWaf) == 0 {
		return false
	}
	if len(options.filterCdn) > 0 && data.itemType == "cdn" {
		for _, filter := range options.filterCdn {
			if filter == data.CdnName {
				return true
			}
		}
	}
	if len(options.filterCloud) > 0 && data.itemType == "cloud" {
		for _, filter := range options.filterCloud {
			if filter == data.CdnName {
				return true
			}
		}
	}
	if len(options.filterWaf) > 0 && data.itemType == "waf" {
		for _, filter := range options.filterWaf {
			if filter == data.CdnName {
				return true
			}
		}
	}
	return false
}

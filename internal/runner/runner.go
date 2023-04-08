package runner

import (
	"bufio"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/mapcidr"
	errorutils "github.com/projectdiscovery/utils/errors"
	iputils "github.com/projectdiscovery/utils/ip"
	urlutils "github.com/projectdiscovery/utils/url"
)

type Runner struct {
	options    *Options
	cdnclient  *cdncheck.Client
	fastdialer *fastdialer.Dialer
}

func NewRunner(options *Options) *Runner {
	runner := &Runner{
		options:   options,
		cdnclient: cdncheck.New(),
	}
	fOption := fastdialer.DefaultOptions
	if len(options.resolvers) > 0 {
		fOption.BaseResolvers = options.resolvers
	}
	fdialer, err := fastdialer.NewDialer(fOption)
	if err != nil {
		if options.verbose {
			gologger.Error().Msgf("%v: fialed to initialize dailer", err.Error())
		}
		return runner
	}
	runner.fastdialer = fdialer
	return runner
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
		r.processInputItem(target, output)
	}
	if r.options.list != "" {
		file, err := os.Open(r.options.list)
		if err != nil {
			if r.options.verbose {
				gologger.Error().Msgf("Could not open input file: %s", err)
			}
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			text := scanner.Text()
			if text != "" {
				r.processInputItem(text, output)
			}
		}
	}
	if r.options.hasStdin {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			text := scanner.Text()
			if text != "" {
				r.processInputItem(text, output)
			}
		}
	}
}

func (r *Runner) waitForData(output chan Output, writer *OutputWriter, wg *sync.WaitGroup) {
	defer wg.Done()
	for receivedData := range output {
		if r.options.json {
			writer.WriteJSON(receivedData)
		} else {
			if r.options.response && !r.options.exclude {
				writer.WriteString(receivedData.String())
			} else {
				writer.WriteString(receivedData.Input)
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
func (r *Runner) processInputItem(input string, output chan Output) {
	// CIDR input
	if _, ipRange, _ := net.ParseCIDR(input); ipRange != nil {
		cidrInputs, err := mapcidr.IPAddressesAsStream(input)
		if err != nil {
			if r.options.verbose {
				gologger.Error().Msgf("Could not parse cidr %s: %s", input, err)
			}
			return
		}
		for cidr := range cidrInputs {
			r.processInputItemSingle(cidr, output)
		}
	} else {
		// Normal input
		r.processInputItemSingle(input, output)
	}
}

func (r *Runner) processInputItemSingle(item string, output chan Output) {
	data := Output{
		Input: item,
	}
	if !iputils.IsIP(item) {
		ipAddr, err := r.resolveToIP(item)
		if err != nil {
			if r.options.verbose {
				gologger.Error().Msgf("Could not parse domain/url %s: %s", item, err)
			}
			return
		}
		item = ipAddr
	}

	parsed := net.ParseIP(item)
	if parsed == nil {
		if r.options.verbose {
			gologger.Error().Msgf("Could not parse IP address: %s", item)
		}
		return
	}
	isCDN, provider, itemType, err := r.cdnclient.Check(parsed)
	if err != nil {
		if r.options.verbose {
			gologger.Error().Msgf("Could not check IP cdn %s: %s", item, err)
		}
		return
	}
	data.itemType = itemType
	data.IP = item
	data.Timestamp = time.Now()

	if r.options.exclude {
		if !isCDN {
			output <- data
		}
		return
	}
	switch itemType {
	case "cdn":
		data.Cdn = isCDN
		data.CdnName = provider
	case "cloud":
		data.Cloud = isCDN
		data.CloudName = provider
	case "waf":
		data.Waf = isCDN
		data.WafName = provider
	}
	if skipped := filterIP(r.options, data); skipped {
		return
	}
	if matched := matchIP(r.options, data); !matched {
		return
	}
	switch {
	case r.options.cdn && data.itemType == "cdn",
		r.options.cloud && data.itemType == "cloud",
		r.options.waf && data.itemType == "waf":
		{
			output <- data
		}
	case (!r.options.cdn && !r.options.waf && !r.options.cloud) && isCDN:
		{
			output <- data
		}
	}
}

func (r *Runner) resolveToIP(domain string) (string, error) {
	url, err := urlutils.Parse(domain)
	if err != nil {
		return domain, err
	}
	dsnData, err := r.fastdialer.GetDNSData(url.Host)
	if err != nil {
		return domain, err
	}
	if len(dsnData.A) < 1 {
		return domain, errorutils.New("fialed to resolve domain")
	}
	return dsnData.A[0], nil
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
			if filter == data.CloudName {
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
			if filter == data.WafName {
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
			if filter == data.CloudName {
				return true
			}
		}
	}
	if len(options.filterWaf) > 0 && data.itemType == "waf" {
		for _, filter := range options.filterWaf {
			if filter == data.WafName {
				return true
			}
		}
	}
	return false
}

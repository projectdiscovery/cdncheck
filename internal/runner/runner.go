package runner

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/logrusorgru/aurora"
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
	aurora     *aurora.Aurora
	writer     *OutputWriter
}

func NewRunner(options *Options) *Runner {
	standardWriter := aurora.NewAurora(!options.NoColor)
	runner := &Runner{
		options:   options,
		cdnclient: cdncheck.New(),
		aurora:    &standardWriter,
	}
	fOption := fastdialer.DefaultOptions
	if len(options.Resolvers) > 0 {
		fOption.BaseResolvers = options.Resolvers
	}
	fdialer, err := fastdialer.NewDialer(fOption)
	if err != nil {
		if options.Verbose {
			gologger.Error().Msgf("%v: fialed to initialize dailer", err.Error())
		}
		return runner
	}
	runner.fastdialer = fdialer
	return runner
}

func (r *Runner) Run() error {
	err := r.configureOutput()
	if err != nil {
		return errors.Wrap(err, "could not configure output")
	}
	defer r.writer.Close()
	output := make(chan Output, 1)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go r.process(output, wg)
	wg.Add(1)
	go r.waitForData(output, wg)
	wg.Wait()
	return nil
}

func (r *Runner) SetWriter(writer io.Writer) error {
	outputWriter, err := NewOutputWriter()
	if err != nil {
		return err
	}
	outputWriter.AddWriters(writer)
	r.writer = outputWriter
	return nil
}

func (r *Runner) process(output chan Output, wg *sync.WaitGroup) {
	defer wg.Done()
	defer close(output)
	for _, target := range r.options.Inputs {
		r.processInputItem(target, output)
	}
	if r.options.List != "" {
		file, err := os.Open(r.options.List)
		if err != nil {
			if r.options.Verbose {
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
	if r.options.HasStdin {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			text := scanner.Text()
			if text != "" {
				r.processInputItem(text, output)
			}
		}
	}
}

func (r *Runner) waitForData(output chan Output, wg *sync.WaitGroup) {
	defer wg.Done()
	var cdnCount, wafCount, cloudCount int
	for receivedData := range output {
		if receivedData.Cdn {
			cdnCount++
		} else if receivedData.Waf {
			wafCount++
		} else if receivedData.Cloud {
			cloudCount++
		}

		if r.options.OnResult != nil {
			r.options.OnResult(receivedData)
		}

		if r.options.Json {
			r.writer.WriteJSON(receivedData)
		} else if r.options.Response && !r.options.Exclude {
			r.writer.WriteString(receivedData.String())
		} else {
			r.writer.WriteString(receivedData.Input)
		}
	}

	// show summary to user
	sw := *r.aurora
	if (cdnCount + wafCount + cloudCount) < 1 {
		gologger.Info().Msgf("No results found.")
		return
	}
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("Found result: %v", (cdnCount + cloudCount + wafCount)))
	builder.WriteString(" (")
	if cdnCount > 0 {
		builder.WriteString(sw.BrightBlue(fmt.Sprintf("CDN: %v", cdnCount)).String())
	}
	if cloudCount > 0 {
		if cdnCount > 0 {
			builder.WriteString(", ")
		}
		builder.WriteString(sw.BrightGreen(fmt.Sprintf("CLOUD: %v", cloudCount)).String())
	}
	if wafCount > 0 {
		if cdnCount > 0 || cloudCount > 0 {
			builder.WriteString(", ")
		}
		builder.WriteString(sw.Yellow(fmt.Sprintf("WAF: %v", wafCount)).String())
	}
	builder.WriteString(")")
	gologger.Info().Msg(builder.String())
}

func (r *Runner) configureOutput() error {
	if r.writer != nil {
		return nil
	}
	outputWriter, err := NewOutputWriter()
	if err != nil {
		return err
	}
	if r.options.OnResult != nil {
		r.writer = outputWriter
		return nil
	}
	outputWriter.AddWriters(os.Stdout)
	if r.options.Output != "" {
		outputFile, err := os.Create(r.options.Output)
		if err != nil {
			return err
		}
		outputWriter.AddWriters(outputFile)
	}
	r.writer = outputWriter
	return nil
}

// processInputItem processes a single input item
func (r *Runner) processInputItem(input string, output chan Output) {
	// CIDR input
	if _, ipRange, _ := net.ParseCIDR(input); ipRange != nil {
		cidrInputs, err := mapcidr.IPAddressesAsStream(input)
		if err != nil {
			if r.options.Verbose {
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
		aurora: r.aurora,
		Input:  item,
	}
	if !iputils.IsIP(item) {
		ipAddr, err := r.resolveToIP(item)
		if err != nil {
			if r.options.Verbose {
				gologger.Error().Msgf("Could not parse domain/url %s: %s", item, err)
			}
			return
		}
		item = ipAddr
	}

	parsed := net.ParseIP(item)
	if parsed == nil {
		if r.options.Verbose {
			gologger.Error().Msgf("Could not parse IP address: %s", item)
		}
		return
	}
	isCDN, provider, itemType, err := r.cdnclient.Check(parsed)
	if err != nil {
		if r.options.Verbose {
			gologger.Error().Msgf("Could not check IP cdn %s: %s", item, err)
		}
		return
	}
	data.itemType = itemType
	data.IP = item
	data.Timestamp = time.Now()

	if r.options.Exclude {
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
	case r.options.Cdn && data.itemType == "cdn",
		r.options.Cloud && data.itemType == "cloud",
		r.options.Waf && data.itemType == "waf":
		{
			output <- data
		}
	case (!r.options.Cdn && !r.options.Waf && !r.options.Cloud) && isCDN:
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
	if len(options.MatchCdn) == 0 && len(options.MatchCloud) == 0 && len(options.MatchWaf) == 0 {
		return true
	}
	if len(options.MatchCdn) > 0 && data.itemType == "cdn" {
		matched := false
		for _, filter := range options.MatchCdn {
			if filter == data.CdnName {
				matched = true
			}
		}
		if matched {
			return true
		}
	}
	if len(options.MatchCloud) > 0 && data.itemType == "cloud" {
		matched := false
		for _, filter := range options.MatchCloud {
			if filter == data.CloudName {
				matched = true
			}
		}
		if matched {
			return true
		}
	}
	if len(options.MatchWaf) > 0 && data.itemType == "waf" {
		matched := false
		for _, filter := range options.MatchWaf {
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
	if len(options.FilterCdn) == 0 && len(options.FilterCloud) == 0 && len(options.FilterWaf) == 0 {
		return false
	}
	if len(options.FilterCdn) > 0 && data.itemType == "cdn" {
		for _, filter := range options.FilterCdn {
			if filter == data.CdnName {
				return true
			}
		}
	}
	if len(options.FilterCloud) > 0 && data.itemType == "cloud" {
		for _, filter := range options.FilterCloud {
			if filter == data.CloudName {
				return true
			}
		}
	}
	if len(options.FilterWaf) > 0 && data.itemType == "waf" {
		for _, filter := range options.FilterWaf {
			if filter == data.WafName {
				return true
			}
		}
	}
	return false
}

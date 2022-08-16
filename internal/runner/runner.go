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
	output := make(chan Output)
	defer close(output)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
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
	}()
	go func() {
		for output := range output {
			if r.options.json {
				if !output.Cdn {
					if !r.options.resp {
						writer.WriteJSON(output)
					}
				} else if r.options.resp {
					writer.WriteJSON(output)
				}
			} else {
				if !output.Cdn {
					if !r.options.resp {
						writer.WriteString(output.String())
					}
				} else if r.options.resp {
					writer.WriteString(output.String())
				}
			}
		}
	}()
	wg.Wait()
	return nil
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
	output <- data

}

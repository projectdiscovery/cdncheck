package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/cdncheck/generate"
	"gopkg.in/yaml.v3"
)

var (
	input  = flag.String("input", "input.yaml", "input.yaml file for processing")
	output = flag.String("output", "cidr_data.json", "output file for generated cidrs")
	token  = flag.String("token", "", "Token for the ipinfo service")
)

func main() {
	flag.Parse()

	if err := process(); err != nil {
		log.Fatalf("[error] Could not process: %s\n", err)
	}
}

func process() error {
	input, err := readCDNInputFile()
	if err != nil {
		return err
	}
	options := &generate.Options{}
	options.ParseFromEnv()
	if *token != "" && options.IPInfoToken == "" {
		options.IPInfoToken = *token
	}

	compiled, err := input.Compile(options)
	if err != nil {
		return err
	}
	// Print compiled details

	outputFile, err := os.Create(*output)
	if err != nil {
		return errors.Wrap(err, "could not create output file")
	}
	defer outputFile.Close()

	// function to trim the last comma from an array
	endOfArray := func(len int) func() string {
		count := 0
		return func() string {
			count++
			if count == int(len) {
				return "\n\t\t]\n"
			}
			return "\n\t\t],\n"
		}
	}
	_, _ = outputFile.WriteString("{\n")

	if len(compiled.CDN) > 0 {
		for provider, items := range compiled.CDN {
			fmt.Printf("[cdn] Got %d items for %s\n", len(items), provider)
		}
		_, _ = outputFile.WriteString(fmt.Sprintf("\t%q: {\n", "cdn"))
		eoArray := endOfArray(len(compiled.CDN))
		for provider, items := range compiled.CDN {
			_, _ = outputFile.WriteString(fmt.Sprintf("\t\t%q: [\n", provider))
			_, _ = outputFile.WriteString(joinQuotedString(items, ","))
			_, _ = outputFile.WriteString(eoArray())
		}
		_, _ = outputFile.WriteString("\t},")
	}

	if len(compiled.WAF) > 0 {
		for provider, items := range compiled.WAF {
			fmt.Printf("[waf] Got %d items for %s\n", len(items), provider)
		}
		_, _ = outputFile.WriteString(fmt.Sprintf("\n\t%q: {\n", "waf"))
		eoArray := endOfArray(len(compiled.WAF))
		for provider, items := range compiled.WAF {
			_, _ = outputFile.WriteString(fmt.Sprintf("\t\t%q: [\n", provider))
			_, _ = outputFile.WriteString(joinQuotedString(items, ","))
			_, _ = outputFile.WriteString(eoArray())
		}
		_, _ = outputFile.WriteString("\t},")
	}

	if len(compiled.Cloud) > 0 {
		for provider, items := range compiled.Cloud {
			fmt.Printf("[cloud] Got %d items for %s\n", len(items), provider)
		}
		_, _ = outputFile.WriteString(fmt.Sprintf("\n\t%q: {\n", "cloud"))
		eoArray := endOfArray(len(compiled.Cloud))
		for provider, items := range compiled.Cloud {
			_, _ = outputFile.WriteString(fmt.Sprintf("\t\t%q: [\n", provider))
			_, _ = outputFile.WriteString(joinQuotedString(items, ","))
			_, _ = outputFile.WriteString(eoArray())
		}
		_, _ = outputFile.WriteString("\t}")
	}
	_, _ = outputFile.WriteString("\n}\n")
	return nil
}

func readCDNInputFile() (*generate.Input, error) {
	var inputItem generate.Input

	file, err := os.Open(*input)
	if err != nil {
		return nil, errors.Wrap(err, "could not read input.yaml file")
	}
	defer file.Close()

	if err := yaml.NewDecoder(file).Decode(&inputItem); err != nil {
		return nil, errors.Wrap(err, "could not decode input.yaml file")
	}
	return &inputItem, nil
}

// joinQuotedString joins strings while quoting them and newline-tabbing them
func joinQuotedString(elems []string, sep string) string {
	n := len(sep) * (len(elems) - 1)
	for i := 0; i < len(elems); i++ {
		n += len(elems[i])
	}
	prefix := "\t\t\t"

	var b strings.Builder
	b.Grow(n)
	b.WriteString(fmt.Sprintf("%s%q", prefix, elems[0]))
	for _, s := range elems[1:] {
		b.WriteString(sep)
		b.WriteString(fmt.Sprintf("\n%s%q", prefix, s))
	}
	return b.String()
}

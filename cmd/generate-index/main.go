package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/cdncheck/generate"
	"gopkg.in/yaml.v3"
)

var (
	input  = flag.String("input", "provider.yaml", "provider file for processing")
	output = flag.String("output", "sources_data.json", "output file for generated sources")
	token  = flag.String("token", "", "Token for the ipinfo service")
)

func main() {
	flag.Parse()

	if err := process(); err != nil {
		log.Fatalf("[error] Could not process: %s\n", err)
	}
}

func process() error {
	options := &generate.Options{}
	options.ParseFromEnv()
	if *token != "" && options.IPInfoToken == "" {
		options.IPInfoToken = *token
	}

	categories, err := parseCategoriesFromFile()
	if err != nil {
		return err
	}

	compiled, err := categories.Compile(options)
	if err != nil {
		return err
	}

	outputFile, err := os.Create(*output)
	if err != nil {
		return errors.Wrap(err, "could not create output file")
	}
	defer outputFile.Close()

	data := cdncheck.InputCompiled{}
	if len(compiled.Common) > 0 {
		for provider, items := range compiled.Common {
			fmt.Printf("[common/fqdn] Defined %d items for %s\n", len(items), provider)
		}
		data.Common = compiled.Common
	}
	if len(compiled.CDN) > 0 {
		for provider, items := range compiled.CDN {
			fmt.Printf("[cdn] Got %d items for %s\n", len(items), provider)
		}
		data.CDN = compiled.CDN
	}

	if len(compiled.WAF) > 0 {
		for provider, items := range compiled.WAF {
			fmt.Printf("[waf] Got %d items for %s\n", len(items), provider)
		}
		data.WAF = compiled.WAF
	}

	if len(compiled.Cloud) > 0 {
		for provider, items := range compiled.Cloud {
			fmt.Printf("[cloud] Got %d items for %s\n", len(items), provider)
		}
		data.Cloud = compiled.Cloud
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return errors.Wrap(err, "could not marshal json")
	}
	_, err = outputFile.Write(jsonData)
	if err != nil {
		return errors.Wrap(err, "could not write to output file")
	}
	return nil
}

func parseCategoriesFromFile() (*generate.Categories, error) {
	file, err := os.Open(*input)
	if err != nil {
		return nil, errors.Wrap(err, "could not read input.yaml file")
	}
	defer file.Close()

	categories := &generate.Categories{}
	if err := yaml.NewDecoder(file).Decode(categories); err != nil {
		return nil, errors.Wrap(err, "could not decode input.yaml file")
	}
	return categories, nil
}

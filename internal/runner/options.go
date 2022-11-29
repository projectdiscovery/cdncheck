package runner

import (
	"fmt"
	"os"
	"time"

	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
)

type Output struct {
	Timestamp time.Time `json:"timestamp,omitempty"`
	Input     string    `json:"input,omitempty"`
	Host      string    `json:"host,omitempty"`
	IP        string    `json:"ip"`
	Cdn       bool      `json:"cdn,omitempty"`
	CdnName   string    `json:"cdn_name,omitempty"`
	Cloud     bool      `json:"cloud,omitempty"`
	CloudName string    `json:"cloud_name,omitempty"`
	Waf       bool      `json:"waf,omitempty"`
	WafName   string    `json:"waf_name,omitempty"`
	itemType  string
}

func (o *Output) String() string {
	commonName := ""
	switch o.itemType {
	case "cdn":
		commonName = o.CdnName
	case "cloud":
		commonName = o.CloudName
	case "waf":
		commonName = o.WafName
	}
	return fmt.Sprintf("%s [%s] [%s]", o.Input, o.itemType, commonName)
}
func (o *Output) StringIP() string {
	return o.IP
}

type Options struct {
	inputs      goflags.StringSlice
	list        string
	response    bool
	hasStdin    bool
	output      string
	version     bool
	json        bool
	cdn         bool
	cloud       bool
	waf         bool
	exclude     bool
	matchCdn    goflags.StringSlice
	matchCloud  goflags.StringSlice
	matchWaf    goflags.StringSlice
	filterCdn   goflags.StringSlice
	filterCloud goflags.StringSlice
	filterWaf   goflags.StringSlice
}

func ParseOptions() *Options {
	opts, err := readFlags()
	if err != nil {
		gologger.Fatal().Msgf("Program Exiting: %s\n", err)
	}
	return opts
}

// readFlags reads the flags and options for the utility
func readFlags() (*Options, error) {
	opts := &Options{}
	opts.hasStdin = fileutil.HasStdin()

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("cdncheck is a tool for identifying the technology associated with ip network addresses.")

	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&opts.inputs, "inputs", "i", nil, "inputs to process", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringVarP(&opts.list, "list", "l", "", "file with inputs to process"),
	)

	flagSet.CreateGroup("detection", "Detection",
		flagSet.BoolVarP(&opts.cdn, "cdn", "", false, "display cdn ip in cli output"),
		flagSet.BoolVarP(&opts.cloud, "cloud", "", false, "display cloud ip in cli output"),
		flagSet.BoolVarP(&opts.waf, "waf", "", false, "display waf ip in cli output"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.BoolVarP(&opts.response, "resp", "", false, "display technology name in cli output"),
		flagSet.StringVarP(&opts.output, "output", "o", "", "write output in plain format to file"),
		flagSet.BoolVarP(&opts.version, "version", "", false, "display version of the project"),
		flagSet.BoolVarP(&opts.json, "json", "", false, "write output in json format to file"),
	)

	flagSet.CreateGroup("matchers", "Matchers",
		flagSet.StringSliceVarP(&opts.matchCdn, "match-cdn", "mcdn", nil, fmt.Sprintf("match host with specified cdn provider (%s)", cdncheck.DefaultCDNProviders), goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&opts.matchCloud, "match-cloud", "mcloud", nil, fmt.Sprintf("match host with specified cloud provider (%s)", cdncheck.DefaultCloudProviders), goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&opts.matchWaf, "match-waf", "mwaf", nil, fmt.Sprintf("match host with specified waf provider (%s)", cdncheck.DefaultWafProviders), goflags.CommaSeparatedStringSliceOptions),
	)

	flagSet.CreateGroup("filters", "Filters",
		flagSet.StringSliceVarP(&opts.filterCdn, "filter-cdn", "fcdn", nil, fmt.Sprintf("filter host with specified cdn provider (%s)", cdncheck.DefaultCDNProviders), goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&opts.filterCloud, "filter-cloud", "fcloud", nil, fmt.Sprintf("filter host with specified cloud provider (%s)", cdncheck.DefaultCloudProviders), goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&opts.filterWaf, "filter-waf", "fwaf", nil, fmt.Sprintf("filter host with specified waf provider (%s)", cdncheck.DefaultWafProviders), goflags.CommaSeparatedStringSliceOptions),
		flagSet.BoolVarP(&opts.exclude, "exclude", "e", false, "exclude detected ip from output"),
	)

	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msgf("Could not parse flags: %s", err)
		os.Exit(0)
	}
	if opts.version {
		gologger.Info().Msgf("Current version: %s", Version)
		os.Exit(0)
	}
	return opts, nil
}

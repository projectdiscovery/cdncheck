package runner

import (
	"fmt"
	"os"
	"time"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
)

type Output struct {
	Timestamp time.Time `json:"timestamp,omitempty"`
	IP        string    `json:"ip"`
	Cdn       bool      `json:"cdn,omitempty"`
	CdnName   string    `json:"cdn_name,omitempty"`
	itemType  string
}

func (o *Output) String() string {
	if o.Cdn {
		return fmt.Sprintf("%s [%s] [%s]", o.IP, o.itemType, o.CdnName)
	}
	return o.IP
}

type Options struct {
	inputs     goflags.StringSlice
	list       string
	resp       bool
	hasStdin   bool
	output     string
	version    bool
	json       bool
	cdn        bool
	cloud      bool
	waf        bool
	matchCdn   goflags.StringSlice
	matchCloud goflags.StringSlice
	matchWaf   goflags.StringSlice
	filterCdn  goflags.StringSlice
	fiterCloud goflags.StringSlice
	filterWaf  goflags.StringSlice
	exclude    bool
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
	flagSet.SetDescription("cdncheck is a utility for ignoring CDN range IPs")

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
		flagSet.BoolVarP(&opts.resp, "resp", "", false, "display technology name in cli output"),
		flagSet.StringVarP(&opts.output, "output", "o", "", "write output in plain format to file"),
		flagSet.BoolVarP(&opts.version, "version", "", false, "display version of the project"),
		flagSet.BoolVarP(&opts.json, "json", "", false, "write output in json format to file"),
	)

	flagSet.CreateGroup("matchers", "Matchers",
		flagSet.StringSliceVarP(&opts.matchCdn, "match-cdn", "mcdn", nil, "match host with specified cdn provider (fastly, incapsula)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&opts.matchCloud, "match-cloud", "mcloud", nil, "match host with specified cloud provider (fastly, incapsula)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&opts.matchWaf, "match-waf", "mwaf", nil, "match host with specified waf provider (fastly, incapsula)", goflags.CommaSeparatedStringSliceOptions),
	)

	flagSet.CreateGroup("filters", "Filters",
		flagSet.StringSliceVarP(&opts.filterCdn, "filter-cdn", "fcdn", nil, "filter host with specified cdn provider (fastly, incapsula)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&opts.fiterCloud, "filter-cloud", "fcloud", nil, "filter host with specified cloud provider (fastly, incapsula)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&opts.filterWaf, "filter-waf", "fwaf", nil, "filter host with specified waf provider (fastly, incapsula)", goflags.CommaSeparatedStringSliceOptions),
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

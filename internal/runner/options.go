package runner

import (
	"fmt"
	"os"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	fileutil "github.com/projectdiscovery/utils/file"
	updateutils "github.com/projectdiscovery/utils/update"
)

type Output struct {
	aurora    *aurora.Aurora
	Timestamp time.Time `json:"timestamp,omitempty"`
	Input     string    `json:"input"`
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
	sw := *o.aurora
	commonName := "[%s]"
	itemType := fmt.Sprintf("[%s]", o.itemType)
	switch o.itemType {
	case "cdn":
		commonName = fmt.Sprintf(commonName, o.CdnName)
		itemType = sw.BrightBlue(itemType).String()
	case "cloud":
		commonName = fmt.Sprintf(commonName, o.CloudName)
		itemType = sw.BrightGreen(itemType).String()
	case "waf":
		commonName = fmt.Sprintf(commonName, o.WafName)
		itemType = sw.Yellow(itemType).String()
	}
	commonName = sw.BrightYellow(commonName).String()
	return fmt.Sprintf("%s %s %s", o.Input, itemType, commonName)
}
func (o *Output) StringIP() string {
	return o.IP
}

type Options struct {
	Inputs             goflags.StringSlice
	Response           bool
	HasStdin           bool
	Output             string
	Version            bool
	Json               bool
	Cdn                bool
	Cloud              bool
	Waf                bool
	Exclude            bool
	Verbose            bool
	NoColor            bool
	Silent             bool
	Debug              bool
	DisableUpdateCheck bool
	MatchCdn           goflags.StringSlice
	MatchCloud         goflags.StringSlice
	MatchWaf           goflags.StringSlice
	FilterCdn          goflags.StringSlice
	FilterCloud        goflags.StringSlice
	FilterWaf          goflags.StringSlice
	Resolvers          goflags.StringSlice
	OnResult           func(r Output)
	MaxRetries         int
}

// configureOutput configures the output logging levels to be displayed on the screen
func configureOutput(options *Options) {
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	} else if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelWarning)
	} else if options.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	} else {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	}

	if options.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	}
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
	opts.HasStdin = fileutil.HasStdin()

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("cdncheck is a tool for identifying the technology associated with dns / ip network addresses.")

	flagSet.CreateGroup("input", "INPUT",
		flagSet.StringSliceVarP(&opts.Inputs, "input", "i", nil, "list of ip / dns to process", goflags.FileCommaSeparatedStringSliceOptions),
	)

	flagSet.CreateGroup("detection", "DETECTION",
		flagSet.BoolVarP(&opts.Cdn, "cdn", "", false, "display only cdn in cli output"),
		flagSet.BoolVarP(&opts.Cloud, "cloud", "", false, "display only cloud in cli output"),
		flagSet.BoolVarP(&opts.Waf, "waf", "", false, "display only waf in cli output"),
	)

	flagSet.CreateGroup("matcher", "MATCHER",
		flagSet.StringSliceVarP(&opts.MatchCdn, "match-cdn", "mcdn", nil, fmt.Sprintf("match host with specified cdn provider (%s)", cdncheck.DefaultCDNProviders), goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&opts.MatchCloud, "match-cloud", "mcloud", nil, fmt.Sprintf("match host with specified cloud provider (%s)", cdncheck.DefaultCloudProviders), goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&opts.MatchWaf, "match-waf", "mwaf", nil, fmt.Sprintf("match host with specified waf provider (%s)", cdncheck.DefaultWafProviders), goflags.CommaSeparatedStringSliceOptions),
	)

	flagSet.CreateGroup("filter", "FILTER",
		flagSet.StringSliceVarP(&opts.FilterCdn, "filter-cdn", "fcdn", nil, fmt.Sprintf("filter host with specified cdn provider (%s)", cdncheck.DefaultCDNProviders), goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&opts.FilterCloud, "filter-cloud", "fcloud", nil, fmt.Sprintf("filter host with specified cloud provider (%s)", cdncheck.DefaultCloudProviders), goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&opts.FilterWaf, "filter-waf", "fwaf", nil, fmt.Sprintf("filter host with specified waf provider (%s)", cdncheck.DefaultWafProviders), goflags.CommaSeparatedStringSliceOptions),
	)

	flagSet.CreateGroup("output", "OUTPUT",
		flagSet.BoolVarP(&opts.Response, "resp", "", false, "display technology name in cli output"),
		flagSet.StringVarP(&opts.Output, "output", "o", "", "write output in plain format to file"),
		flagSet.BoolVarP(&opts.Verbose, "verbose", "v", false, "display verbose output"),
		flagSet.BoolVarP(&opts.Json, "jsonl", "j", false, "write output in json(line) format"),
		flagSet.BoolVarP(&opts.NoColor, "no-color", "nc", false, "disable colors in cli output"),
		flagSet.BoolVarP(&opts.Version, "version", "", false, "display version of the project"),
		flagSet.BoolVar(&opts.Silent, "silent", false, "only display results in output"),
	)

	flagSet.CreateGroup("config", "CONFIG",
		flagSet.StringSliceVarP(&opts.Resolvers, "resolver", "r", nil, "list of resolvers to use (file or comma separated)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.BoolVarP(&opts.Exclude, "exclude", "e", false, "exclude detected ip from output"),
		flagSet.IntVar(&opts.MaxRetries, "retry", 2, "maximum number of retries for dns resolution (must be at least 1)"),
	)

	flagSet.CreateGroup("update", "UPDATE",
		flagSet.CallbackVarP(GetUpdateCallback(), "update", "up", "update cdncheck to latest version"),
		flagSet.BoolVarP(&opts.DisableUpdateCheck, "disable-update-check", "duc", false, "disable automatic cdncheck update check"),
	)

	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msgf("Could not parse flags: %s", err)
		os.Exit(0)
	}

	// configure output option
	configureOutput(opts)
	// shows banner
	showBanner()

	if opts.Version {
		gologger.Info().Msgf("Current version: %s", version)
		os.Exit(0)
	}

	if !opts.DisableUpdateCheck {
		latestVersion, err := updateutils.GetToolVersionCallback("cdncheck", version)()
		if err != nil {
			if opts.Verbose {
				gologger.Error().Msgf("cdncheck version check failed: %v", err.Error())
			}
		} else {
			gologger.Info().Msgf("Current cdncheck version %v %v", version, updateutils.GetVersionDescription(version, latestVersion))
		}
	}

	return opts, nil
}

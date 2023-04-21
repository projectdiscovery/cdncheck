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
	inputs             goflags.StringSlice
	list               string
	response           bool
	hasStdin           bool
	output             string
	version            bool
	json               bool
	cdn                bool
	cloud              bool
	waf                bool
	exclude            bool
	verbose            bool
	noColor            bool
	silent             bool
	debug              bool
	disableUpdateCheck bool
	matchCdn           goflags.StringSlice
	matchCloud         goflags.StringSlice
	matchWaf           goflags.StringSlice
	filterCdn          goflags.StringSlice
	filterCloud        goflags.StringSlice
	filterWaf          goflags.StringSlice
	resolvers          goflags.StringSlice
}

// configureOutput configures the output logging levels to be displayed on the screen
func configureOutput(options *Options) {
	if options.silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	} else if options.verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelWarning)
	} else if options.debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	} else {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	}

	if options.noColor {
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

	flagSet.CreateGroup("update", "Update",
		flagSet.CallbackVarP(GetUpdateCallback(), "update", "up", "update cdncheck to latest version"),
		flagSet.BoolVarP(&opts.disableUpdateCheck, "disable-update-check", "duc", false, "disable automatic cdncheck update check"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.BoolVarP(&opts.response, "resp", "", false, "display technology name in cli output"),
		flagSet.StringVarP(&opts.output, "output", "o", "", "write output in plain format to file"),
		flagSet.BoolVarP(&opts.version, "version", "", false, "display version of the project"),
		flagSet.BoolVarP(&opts.verbose, "verbose", "v", false, "display verbose output"),
		flagSet.BoolVarP(&opts.json, "jsonl", "j", false, "write output in json(line) format"),
		flagSet.BoolVarP(&opts.noColor, "no-color", "nc", false, "disable colors in cli output"),
		flagSet.BoolVar(&opts.silent, "silent", false, "only display results in output"),
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

	flagSet.CreateGroup("config", "Config",
		flagSet.StringSliceVarP(&opts.resolvers, "resolver", "r", nil, "list of resolvers to use (file or comma separated)", goflags.CommaSeparatedStringSliceOptions),
	)

	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msgf("Could not parse flags: %s", err)
		os.Exit(0)
	}

	// configure output option
	configureOutput(opts)
	// shows banner
	showBanner()

	if !opts.disableUpdateCheck {
		latestVersion, err := updateutils.GetToolVersionCallback("cdncheck", version)()
		if err != nil {
			if opts.verbose {
				gologger.Error().Msgf("cdncheck version check failed: %v", err.Error())
			}
		} else {
			gologger.Info().Msgf("Current cdncheck version %v %v", version, updateutils.GetVersionDescription(version, latestVersion))
		}
	}

	if opts.version {
		gologger.Info().Msgf("Current version: %s", version)
		os.Exit(0)
	}
	return opts, nil
}

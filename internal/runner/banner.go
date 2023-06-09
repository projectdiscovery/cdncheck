package runner

import (
	"github.com/projectdiscovery/gologger"
	updateutils "github.com/projectdiscovery/utils/update"
)

const banner = `
            __           __              __  
  _________/ /___  _____/ /_  ___  _____/ /__
 / ___/ __  / __ \/ ___/ __ \/ _ \/ ___/ //_/
/ /__/ /_/ / / / / /__/ / / /  __/ /__/ ,<   
\___/\__,_/_/ /_/\___/_/ /_/\___/\___/_/|_|
`

// version is the current version of cdncheck
const version = `v1.0.9`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")
}

// GetUpdateCallback returns a callback function that updates cdncheck
func GetUpdateCallback() func() {
	return func() {
		showBanner()
		updateutils.GetUpdateToolCallback("cdncheck", version)()
	}
}

package cdncheck

import (
	_ "embed"
	"encoding/json"

	"github.com/projectdiscovery/gologger"
)

//go:embed cidr_data.json
var data string

var generatedData InputCompiled

func init() {
	if err := json.Unmarshal([]byte(data), &generatedData); err != nil {
		gologger.Fatal().Msgf("Could not parse cidr data: %s", err)
	}
}

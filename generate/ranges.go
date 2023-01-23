package generate

import (
	"io"
	"net/http"
	"strings"
)

type scraperNameFuncPair struct {
	name    string
	scraper scraperFunc
}

var scraperTypeToScraperMap = map[string][]scraperNameFuncPair{
	"cdn": {},
	"waf": {
		{name: "incapsula", scraper: scrapeIncapsula},
	},
	"cloud": {},
}

type scraperFunc func(httpClient *http.Client) ([]string, error)

// scrapeIncapsula scrapes incapsula firewall's CIDR ranges from their API
func scrapeIncapsula(httpClient *http.Client) ([]string, error) {
	req, err := http.NewRequest(http.MethodPost, "https://my.incapsula.com/api/integration/v1/ips", strings.NewReader("resp_format=text"))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	body := string(data)

	cidrs := cidrRegex.FindAllString(body, -1)
	if len(cidrs) == 0 {
		return nil, errNoCidrFound
	}
	return cidrs, nil
}

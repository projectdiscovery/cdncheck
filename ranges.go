package cdncheck

import (
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
)

var cidrRegex = regexp.MustCompile(`[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,3}`)

type scraperFunc func(httpClient *http.Client) ([]string, error)

// scrapeCloudflare scrapes cloudflare firewall's CIDR ranges from their API
func scrapeCloudflare(httpClient *http.Client) ([]string, error) {
	resp, err := httpClient.Get("https://www.cloudflare.com/ips-v4")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	body := string(data)

	cidrs := cidrRegex.FindAllString(body, -1)
	return cidrs, nil
}

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

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	body := string(data)

	cidrs := cidrRegex.FindAllString(body, -1)
	return cidrs, nil
}

// scrapeAkamai scrapes akamai firewall's CIDR ranges from ipinfo
func scrapeAkamai(httpClient *http.Client) ([]string, error) {
	resp, err := httpClient.Get("https://ipinfo.io/AS12222")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	body := string(data)

	cidrs := cidrRegex.FindAllString(body, -1)
	return cidrs, nil
}

// scrapeSucuri scrapes sucuri firewall's CIDR ranges from ipinfo
func scrapeSucuri(httpClient *http.Client) ([]string, error) {
	resp, err := httpClient.Get("https://ipinfo.io/AS30148")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	body := string(data)

	cidrs := cidrRegex.FindAllString(body, -1)
	return cidrs, nil
}

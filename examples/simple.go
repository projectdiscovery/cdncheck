package main

import (
	"fmt"
	"net"

	"github.com/projectdiscovery/cdncheck"
)

func main() {
	client := cdncheck.New()
	ip := net.ParseIP("173.245.48.12")

	// checks if an IP is contained in the cdn denylist
	matched, val, err := client.CheckCDN(ip)
	if err != nil {
		panic(err)
	}

	if matched {
		fmt.Printf("%v is a %v\n", ip, val)
	} else {
		fmt.Printf("%v is not a CDN\n", ip)
	}

	// checks if an IP is contained in the cloud denylist
	matched, val, err = client.CheckCloud(ip)
	if err != nil {
		panic(err)
	}

	if matched {
		fmt.Printf("%v is a %v\n", ip, val)
	} else {
		fmt.Printf("%v is not a Cloud\n", ip)
	}

	// checks if an IP is contained in the waf denylist
	matched, val, err = client.CheckWAF(ip)
	if err != nil {
		panic(err)
	}

	if matched {
		fmt.Printf("%v WAF is %v\n", ip, val)
	} else {
		fmt.Printf("%v is not a WAF\n", ip)
	}
}

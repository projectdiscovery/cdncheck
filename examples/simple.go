package main

import (
	"log"
	"net"

	"github.com/projectdiscovery/cdncheck"
)

func main() {
	client := cdncheck.New()
	if found, _, _, err := client.Check(net.ParseIP("173.245.48.12")); found && err == nil {
		log.Println("ip is part of cdn")
	}
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/projectdiscovery/cdncheck"
)

var (
	cdncheckData      []byte
	cdncehckDataMutex = &sync.RWMutex{}

	addr = flag.String("addr", "127.0.0.1:80", "Address to listen cdncheck server on")
)

func main() {
	flag.Parse()

	var cancel context.CancelFunc
	go func() {
		cancel = cdncheckWorker()
	}()
	cdncheckRefreshDataFunc()

	http.HandleFunc("/", cdncheckHandler)
	if err := http.ListenAndServe(*addr, http.DefaultServeMux); err != nil {
		cancel()
		panic(err)
	}
}

func cdncheckWorker() context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())

	ticker := time.NewTicker(24 * time.Hour)
	go func() {
		for {
			select {
			case <-ticker.C:
				cdncheckRefreshDataFunc()
			case <-ctx.Done():
				ticker.Stop()
				return
			default:
				continue
			}
		}
	}()
	return cancel
}

func cdncheckRefreshDataFunc() {
	log.Printf("[%s] Refreshing cdncheck data from providers\n", time.Now().String())

	client, err := cdncheck.New()
	if err != nil {
		log.Printf("[err] could not create cdncheck client: %s\n", err)
		return
	}
	data := client.Ranges()

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(data); err != nil {
		log.Printf("[err] could not json encode cdn data: %s\n", err)
		return
	}

	cdncehckDataMutex.Lock()
	cdncheckData = buf.Bytes()
	cdncehckDataMutex.Unlock()
}

func cdncheckHandler(w http.ResponseWriter, r *http.Request) {
	cdncehckDataMutex.RLock()
	data := cdncheckData
	cdncehckDataMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	_, _ = w.Write(data)
}

package generate

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

func TestFetchInputItem_MergesMultipleURLsPerProvider(t *testing.T) {
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("10.0.0.0/24\n10.0.1.0/24\n"))
	}))
	defer srv1.Close()
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("10.0.1.0/24\n10.0.2.0/24\n"))
	}))
	defer srv2.Close()

	cat := &Category{
		URLs: map[string][]string{
			"provider": {srv1.URL, srv2.URL},
		},
	}
	data := map[string][]string{}
	if err := cat.fetchInputItem(&Options{}, data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := append([]string(nil), data["provider"]...)
	sort.Strings(got)
	want := []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"}
	if !equalStrings(got, want) {
		t.Fatalf("merged cidrs = %v, want %v", got, want)
	}
}

func TestFetchInputItem_ContinuesOnURLError(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("10.0.0.0/24\n"))
	}))
	defer good.Close()

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	bad.Close() // force connection refused for predictable failure

	cat := &Category{
		URLs: map[string][]string{
			"ok":      {good.URL},
			"failing": {bad.URL},
		},
	}
	data := map[string][]string{}
	err := cat.fetchInputItem(&Options{}, data)
	if err == nil {
		t.Fatalf("expected error for failing provider")
	}
	if !strings.Contains(err.Error(), "failing") {
		t.Fatalf("error should reference failing provider, got %q", err.Error())
	}
	if got := data["ok"]; len(got) != 1 || got[0] != "10.0.0.0/24" {
		t.Fatalf("ok provider data = %v, want [10.0.0.0/24]", got)
	}
	if _, exists := data["failing"]; exists {
		t.Fatalf("failing provider should not have populated data, got %v", data["failing"])
	}
}

func TestFetchInputItem_StaticCIDRsMergedWithURLs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("10.0.1.0/24\n"))
	}))
	defer srv.Close()

	cat := &Category{
		CIDR: map[string][]string{
			"provider": {"10.0.0.0/24"},
		},
		URLs: map[string][]string{
			"provider": {srv.URL},
		},
	}
	data := map[string][]string{}
	if err := cat.fetchInputItem(&Options{}, data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := append([]string(nil), data["provider"]...)
	sort.Strings(got)
	want := []string{"10.0.0.0/24", "10.0.1.0/24"}
	if !equalStrings(got, want) {
		t.Fatalf("merged cidrs = %v, want %v", got, want)
	}
}

func TestFetchInputItem_NoAuthSkipsASNNotURLs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("10.0.0.0/24\n"))
	}))
	defer srv.Close()

	cat := &Category{
		URLs: map[string][]string{
			"provider": {srv.URL},
		},
		ASN: map[string][]string{
			"asn-only": {"AS12345"},
		},
	}
	data := map[string][]string{}
	if err := cat.fetchInputItem(&Options{}, data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data["provider"]) != 1 {
		t.Fatalf("expected URL provider populated when no token, got %v", data["provider"])
	}
	if _, ok := data["asn-only"]; ok {
		t.Fatalf("ASN-only provider should be skipped when no token, got %v", data["asn-only"])
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

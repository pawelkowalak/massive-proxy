package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

var (
	httpAddr  = flag.String("http", ":8080", "HTTP address")
	httpsAddr = flag.String("https", ":443", "HTTPS address")
	dev       = flag.Bool("dev", false, "Development mode")
)

// HostSwitch maps host names to http.Handlers.
type HostSwitch map[string]http.Handler

// Implement the ServerHTTP method on our new type.
func (hs HostSwitch) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	handler, ok := hs[r.Host]
	if !ok {
		http.Error(w, "Forbidden", 403)
		return
	}
	handler.ServeHTTP(w, r)
}

// Registry maps host names to backends.
type Registry map[string]string

var reg = Registry{
	"www.homedroids.io":   "localhost:9091",
	"www.spiffystyle.com": "localhost:9092",
}

// Hosts returns slice of host names supported by Registry.
func (r Registry) Hosts() []string {
	domains := make([]string, len(reg))
	for d := range reg {
		domains = append(domains, d)
	}
	return domains
}

func newHostSwitch(reg Registry) HostSwitch {
	hs := make(HostSwitch)
	for h, t := range reg {
		proxy := httputil.NewSingleHostReverseProxy(&url.URL{
			Scheme: "http",
			Host:   t,
		})
		router := http.NewServeMux()
		router.Handle("/", proxy)
		hs[h] = router
	}
	return hs
}

func main() {
	flag.Parse()
	log.Println("Starting")

	client := &acme.Client{}
	if *dev {
		client = &acme.Client{
			DirectoryURL: "https://acme-staging.api.letsencrypt.org/directory",
		}
	}
	m := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(reg.Hosts()...),
		Cache:      autocert.DirCache("certs"),
		Client:     client,
	}
	hs := newHostSwitch(reg)
	s := &http.Server{
		Addr:      ":443",
		Handler:   hs,
		TLSConfig: &tls.Config{GetCertificate: m.GetCertificate},
	}
	log.Fatal(s.ListenAndServeTLS("", ""))
}

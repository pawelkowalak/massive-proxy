package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"encoding/json"

	"github.com/coreos/etcd/client"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

var (
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
	"www.homedroids.io":      "localhost:9091",
	"www.monkeypatching.com": "localhost:9092",
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
	log.Printf("Starting (dev=%t)", *dev)

	c, err := client.New(client.Config{
		Endpoints:               []string{"http://127.0.0.1:2379"},
		Transport:               client.DefaultTransport,
		HeaderTimeoutPerRequest: time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}
	etc := client.NewKeysAPI(c)
	// set "/foo" key with "bar" value
	resp, err := etc.Set(context.Background(), "/services/backends/monkeypatching", `{ "fqdn": "www.monkeypatching.com", "endpoint": "localhost:9092", "version": "deadbeef" }`, nil)
	if err != nil {
		log.Fatal(err)
	}
	// print common key info
	log.Printf("Set is done. Metadata is %q\n", resp)

	// get "/foo" key's value
	reg, err := genRegistry(etc)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for range time.Tick(time.Second) {
			log.Println("refreshing registry")
			reg, err := genRegistry(etc)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("registry %+v", reg)
		}
	}()

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
		Addr:         *httpsAddr,
		Handler:      hs,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		// IdleTimeout:  120 * time.Second,
		TLSConfig: &tls.Config{
			PreferServerCipherSuites: true,
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				// tls.X25519, // Go 1.8 only
			},
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				// tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, // Go 1.8 only
				// tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,   // Go 1.8 only
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			GetCertificate: m.GetCertificate,
		},
	}
	log.Fatal(s.ListenAndServeTLS("", ""))
}

//{ "fqdn": "www.monkeypatching.com", "endpoint": "localhost:9092", "version": "deadbeef" }
type backend struct {
	FQDN     string `json:"fqdn"`
	Endpoint string `json:"endpoint"`
	Version  string `json:"version"`
}

func genRegistry(etc client.KeysAPI) (Registry, error) {
	resp, err := etc.Get(context.Background(), "/services/backends", nil)
	if err != nil {
		return nil, fmt.Errorf("can't get backends from etcd: %v", err)
	}
	reg := make(Registry)
	for _, n := range resp.Node.Nodes {
		b := &backend{}
		if err := json.Unmarshal([]byte(n.Value), b); err != nil {
			return nil, fmt.Errorf("can't decode backend: %v", err)
		}
		reg[b.FQDN] = b.Endpoint
	}
	return reg, nil
}

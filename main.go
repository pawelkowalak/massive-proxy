package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

var (
	httpAddr  = flag.String("http", ":8080", "HTTP address")
	httpsAddr = flag.String("https", ":443", "HTTPS address")
	dev       = flag.Bool("dev", false, "Development mode")
)

type Registry map[string][]string

// ServiceRegistry is a local registry of services/versions
var ServiceRegistry = Registry{
	"www.homedroids.io": {
		"localhost:9091",
		"localhost:9092",
	},
}

func NewMultipleHostReverseProxy(reg Registry) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = req.Host
		},
		Transport: &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return http.ProxyFromEnvironment(req)
			},
			Dial: func(network, addr string) (net.Conn, error) {
				return loadBalance(network, addr, reg)
			},
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
}

func loadBalance(network, addr string, reg Registry) (net.Conn, error) {
	addr = strings.Split(addr, ":")[0]
	endpoints, ok := reg[addr]
	if !ok {
		return nil, fmt.Errorf("Not supported host: %v", addr)
	}
	for {
		// No more endpoint, stop
		if len(endpoints) == 0 {
			break
		}
		// Select a random endpoint
		i := rand.Int() % len(endpoints)
		endpoint := endpoints[i]

		// Try to connect
		conn, err := net.Dial(network, endpoint)
		if err != nil {
			// reg.Failure(serviceName, serviceVersion, endpoint, err)
			// Failure: remove the endpoint from the current list and try again.
			println("can't call endpoint ", i)
			endpoints = append(endpoints[:i], endpoints[i+1:]...)
			continue
		}
		// Success: return the connection.
		return conn, nil
	}
	// No available endpoint.
	return nil, fmt.Errorf("No endpoint available for %s", addr)
}

func main() {
	flag.Parse()
	log.Println("Starting")

	// hdRouter := http.NewServeMux()
	// hdRouter.Handle("/", goproxy.NewMultipleHostReverseProxy(ServiceRegistry))
	proxy := NewMultipleHostReverseProxy(ServiceRegistry)
	http.Handle("/", proxy)
	// hdRouter.Handler("GET", "/assets/*filepath", http.StripPrefix("/assets", http.FileServer(http.Dir("web/assets"))))
	// hdRouter.NotFound = http.HandlerFunc(notFound)

	// hs := make(HostSwitch)
	// hs["spiffystyle:8080"] = ssRouter
	// hs["www.homedroids.io"] = hdRouter

	// if err := http.ListenAndServe(*listen, hs); err != nil {
	// log.Printf("Can't start HTTP: %v", err)
	// }
	client := &acme.Client{}
	if *dev {
		client = &acme.Client{
			DirectoryURL: "https://acme-staging.api.letsencrypt.org/directory",
		}
	}
	m := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist("www.homedroids.io"),
		Cache:      autocert.DirCache("certs"),
		Client:     client,
	}
	s := &http.Server{
		Addr:      ":443",
		TLSConfig: &tls.Config{GetCertificate: m.GetCertificate},
	}
	log.Fatal(s.ListenAndServeTLS("", ""))
}

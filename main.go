/*
 * main.go
 *	TLS server that autogens certificates.
 *
 * $ go run main.go ca # generate CA
 * $ cat ca.pem >> /etc/ssl/certs/ca-certificates.crt
 * $ PORT=443 go run main.go    # run TLS server
 *
 * $ echo '127.0.0.1 api.github.com' >> /etc/hosts
 * $ curl https://api.github.com/foo/bar
 *
 * $ TOKEN=<a github token here> PORT=443 go run main.go
 * $ export GH_TOKEN=TOKEN
 * $ gh auth status
 */
package main

import (
	"crypto"
	"crypto/ecdsa"
	//"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	//"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru/v2"

	"github.com/superfly/tokenizer"
)

const DefaultUrl = "https://api.github.com"
const DefaultProxy = "https://tokenizer.fly.io"
const DefaultProxyAuth = "proxyauthtoken"
const DefaultPort = "443"
const CertOrgName = "Fly.io TLS Proxy"
const GraceTime = 5 * time.Minute
const CertLife = time.Hour
const CALife = 90 * 24 * time.Hour

var CA *tls.Certificate

func WriteX509KeyPair(cert *tls.Certificate, certFile, keyFile string) error {
	if err := writeCertPem(cert, certFile); err != nil {
		return err
	}

	if err := writeKeyPem(cert, keyFile); err != nil {
		return err
	}
	return nil
}

func writeCertPem(cert *tls.Certificate, fn string) error {
	bs := cert.Certificate[0]
	f, err := os.Create(fn)
	if err != nil {
		return fmt.Errorf("%s: %w", fn, err)
	}
	defer f.Close()

	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: bs}); err != nil {
		return fmt.Errorf("%s pem.Encode: %w", fn, err)
	}

	return nil
}

func writeKeyPem(cert *tls.Certificate, fn string) error {
	f, err := os.OpenFile(fn, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("%s: %w", fn, err)
	}
	defer f.Close()

	bs, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return fmt.Errorf("%s: x509.MarshalPKCS8PrivateKey: %w", fn, err)
	}

	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: bs}); err != nil {
		return fmt.Errorf("%s pem.Encode: %w", fn, err)
	}

	return nil
}

func newTlsCert(host string, isCA bool) (*tls.Certificate, error) {
	//_, priv, err := ed25519.GenerateKey(rand.Reader)
	//priv, err := rsa.GenerateKey(rand.Reader, 2048)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("GenerateKey: %w", err)
	}

	cname := host
	names := []string{host}
	keyUsage := x509.KeyUsageDigitalSignature
	now := time.Now()
	notBefore := now.Add(-time.Hour)
	notAfter := now.Add(CertLife)

	if isCA {
		keyUsage |= x509.KeyUsageCertSign
		names = nil
		notAfter = now.Add(CALife)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("rand.Int: %w", err)
	}

	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            []string{CertOrgName},
			Organization:       []string{CertOrgName},
			OrganizationalUnit: []string{CertOrgName},
			Locality:           []string{CertOrgName},
			Province:           []string{CertOrgName},
			CommonName:         cname,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		DNSNames: names,
		IsCA:     isCA,
	}

	ca := cert
	caPriv := crypto.PrivateKey(priv)
	if !isCA {
		if CA == nil {
			return nil, fmt.Errorf("CA is not loaded")
		}
		ca = CA.Leaf
		caPriv = CA.PrivateKey
	}

	pubBs, err := x509.CreateCertificate(rand.Reader, cert, ca, priv.Public(), caPriv)
	if err != nil {
		return nil, fmt.Errorf("x509.CreateCertificate: %w", err)
	}

	certChain := [][]byte{pubBs}
	if !isCA {
		certChain = append(certChain, CA.Certificate...)
	}

	tlsCert := &tls.Certificate{
		Certificate: certChain,
		PrivateKey:  priv,
		Leaf:        cert,
	}
	return tlsCert, nil
}

func makeCA() error {
	cert, err := newTlsCert(CertOrgName+" CA", true)
	if err != nil {
		return err
	}

	return WriteX509KeyPair(cert, "ca.pem", "ca-key.pem")
}

func loadCA() error {
	ca, err := tls.LoadX509KeyPair("ca.pem", "ca-key.pem")
	if err != nil {
		return err
	}
	CA = &ca
	return nil
}

type Server struct {
	certCache *lru.Cache[string, *tls.Certificate]
	url       string
	proxy     string
	proxyAuth string
}

func newServer(url, proxy, proxyAuth string) (*Server, error) {
	cache, err := lru.New[string, *tls.Certificate](1024)
	if err != nil {
		return nil, err
	}

	s := &Server{
		certCache: cache,
		url:       url,
		proxy:     proxy,
		proxyAuth: proxyAuth,
	}
	return s, nil
}

func (p *Server) getCachedCert(name string) *tls.Certificate {
	if cert, ok := p.certCache.Get(name); ok {
		stillValid := time.Now().Add(GraceTime).Before(cert.Leaf.NotAfter)
		if stillValid {
			return cert
		}

		p.certCache.Remove(name)
	}
	return nil
}

func (p *Server) getCertificate(sni *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if cert := p.getCachedCert(sni.ServerName); cert != nil {
		log.Printf("reusing cert for %s\n", sni.ServerName)
		return cert, nil
	}

	log.Printf("generate cert for %s\n", sni.ServerName)
	cert, err := newTlsCert(sni.ServerName, false)
	if err != nil {
		return nil, err
	}
	p.certCache.Add(sni.ServerName, cert)
	return cert, nil
}

func copyHeaders(targ, src http.Header) {
	for k, vs := range src {
		targ[k] = vs
	}
}

func getAuth(hdr string) string {
	if hdr == "" {
		return ""
	}

	// take just the last word, ie "Authorization: Bearer foobar" -> "foobar".
	ws := strings.Split(hdr, " ")
	return ws[len(ws)-1]
}

func printHeaders(s string, hdr http.Header) {
	log.Printf("%s:", s)
	for k, v := range hdr {
		log.Printf("  %s=%v", k, v)
	}
}

func (p *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	url := fmt.Sprintf("%s%s", p.url, req.URL)
	log.Printf("serve %s %s", req.Method, url)
	errResp := func(status int, err error) {
		w.WriteHeader(status)
		log.Printf("%v", err)
		fmt.Fprintf(w, "%v\n", err)
	}

	// Take authorization header and use as the sealed secret.
	auth := getAuth(req.Header.Get("Authorization"))
	if auth == "" {
		errResp(http.StatusUnauthorized, fmt.Errorf("missing auth header"))
		return
	}
	req.Header.Del("Authorization")

	// Get a client that proxies to the tokenizer with the sealed secret.
	cl, err := tokenizer.Client(
		p.proxy,
		tokenizer.WithAuth(p.proxyAuth),
		tokenizer.WithSecret(auth, nil),
	)
	if err != nil {
		errResp(http.StatusInternalServerError, fmt.Errorf("tokenizer.Client: %w", err))
		return
	}

	ctx := req.Context()
	preq, err := http.NewRequestWithContext(ctx, req.Method, url, req.Body)
	if err != nil {
		errResp(http.StatusInternalServerError, fmt.Errorf("NewRequestWithContext: %w", err))
		return
	}

	copyHeaders(preq.Header, req.Header)
	presp, err := cl.Do(preq)
	if err != nil {
		// TODO: better error translation, StatusBadGateway/StatusServiceUnavailable/StatusGatewayTimeout
		errResp(http.StatusGatewayTimeout, err)
		return
	}

	log.Printf("serve %s %s -> %d %q", req.Method, url, presp.StatusCode, presp.Status)
	copyHeaders(w.Header(), presp.Header)
	w.WriteHeader(presp.StatusCode)
	if _, err := io.Copy(w, presp.Body); err != nil {
		log.Printf("copying response: %v", err)
	}
}

func getenv(varName, defval string) string {
	if s := os.Getenv(varName); s != "" {
		return s
	}
	return defval
}

func main() {
	url := getenv("URL", DefaultUrl)
	proxy := getenv("PROXY", DefaultProxy)
	proxyAuth := getenv("PROXYAUTH", DefaultProxyAuth)
	port := getenv("PORT", DefaultPort)

	if len(os.Args) > 1 && os.Args[1] == "ca" {
		log.Printf("making CA\n")
		if err := makeCA(); err != nil {
			log.Printf("makeCA: %v\n", err)
		} else {
			log.Printf("write CA files\n")
		}
		return
	}

	if err := loadCA(); err != nil {
		log.Printf("loadCA: %v\n", err)
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "test" {
		log.Printf("running test\n")
		cert, err := newTlsCert("www.thenewsh.com", false)
		if err != nil {
			log.Printf("newTlsCert: %v\n", err)
			return
		}
		if err := WriteX509KeyPair(cert, "host.pem", "host-key.pem"); err != nil {
			log.Printf("%v\n", err)
			return
		}
		return
	}

	log.Printf("running server\n")
	serv, err := newServer(url, proxy, proxyAuth)
	if err != nil {
		log.Printf("newServer: %v\n", err)
		return
	}

	srv := &http.Server{
		Addr:    fmt.Sprintf("[::1]:%s", port),
		Handler: serv,
		TLSConfig: &tls.Config{
			GetCertificate: serv.getCertificate,
		},
	}

	log.Fatal(srv.ListenAndServeTLS("", ""))
}

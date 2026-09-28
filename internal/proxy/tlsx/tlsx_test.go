package tlsx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

func genCert(t *testing.T, names ...string) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              names,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func TestCertStoreExactMatch(t *testing.T) {
	s := NewCertStore()
	a, b := genCert(t, "a.example"), genCert(t, "b.example")
	s.Replace([]Cert{{Names: []string{"a.example"}, Cert: a}, {Names: []string{"b.example"}, Cert: b}})

	got, err := s.GetCertificate(&tls.ClientHelloInfo{ServerName: "b.example"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got != b {
		t.Error("resolved the wrong certificate")
	}
}

func TestCertStoreIsCaseAndDotInsensitive(t *testing.T) {
	s := NewCertStore()
	c := genCert(t, "a.example")
	s.Replace([]Cert{{Names: []string{"A.Example"}, Cert: c}})
	if _, err := s.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.example."}); err != nil {
		t.Errorf("GetCertificate: %v", err)
	}
}

func TestCertStoreWildcard(t *testing.T) {
	s := NewCertStore()
	w := genCert(t, "*.example")
	s.Replace([]Cert{{Names: []string{"*.example"}, Cert: w}})

	if _, err := s.GetCertificate(&tls.ClientHelloInfo{ServerName: "api.example"}); err != nil {
		t.Errorf("wildcard did not match: %v", err)
	}
}

func TestCertStoreExactBeatsWildcard(t *testing.T) {
	s := NewCertStore()
	w, e := genCert(t, "*.example"), genCert(t, "api.example")
	s.Replace([]Cert{{Names: []string{"*.example"}, Cert: w}, {Names: []string{"api.example"}, Cert: e}})

	got, _ := s.GetCertificate(&tls.ClientHelloInfo{ServerName: "api.example"})
	if got != e {
		t.Error("wildcard shadowed the exact match")
	}
}

func TestUploadedCertificateIsNotASilentCatchAll(t *testing.T) {
	s := NewCertStore()
	s.Replace([]Cert{{Names: []string{"one.example"}, Cert: genCert(t, "one.example")}})

	if _, err := s.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example"}); err == nil {
		t.Error("a certificate for one host was served for another")
	}
}

func TestCertStoreDefaultFallback(t *testing.T) {
	s := NewCertStore()
	a, d := genCert(t, "a.example"), genCert(t, "default.example")
	s.Replace([]Cert{{Names: []string{"a.example"}, Cert: a}, {Names: []string{"default.example"}, Default: true, Cert: d}})

	got, err := s.GetCertificate(&tls.ClientHelloInfo{ServerName: "unknown.example"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got != d {
		t.Error("did not fall back to the default certificate")
	}
}

func TestCertStoreEmptyErrors(t *testing.T) {
	s := NewCertStore()
	_, err := s.GetCertificate(&tls.ClientHelloInfo{ServerName: "x.example"})
	if !errors.Is(err, ErrNoCertificate) {
		t.Errorf("err = %v, want ErrNoCertificate", err)
	}
}

func TestCertStoreReplaceIsLive(t *testing.T) {
	s := NewCertStore()
	s.Replace([]Cert{{Names: []string{"a.example"}, Cert: genCert(t, "a.example")}})
	if s.Len() != 1 {
		t.Fatalf("Len = %d", s.Len())
	}
	s.Replace([]Cert{{Names: []string{"b.example", "*.c.example"}, Cert: genCert(t, "b.example")}})
	if s.Len() != 2 {
		t.Errorf("Len = %d, want 2 after replace", s.Len())
	}
	if _, err := s.GetCertificate(&tls.ClientHelloInfo{ServerName: "x.c.example"}); err != nil {
		t.Errorf("new wildcard not live: %v", err)
	}
}

// TestHandshakeAndFingerprintThroughListener runs a real HTTPS request through
// the peeking listener: the handshake must succeed and the handler must see a
// fingerprint.
func TestHandshakeAndFingerprintThroughListener(t *testing.T) {
	store := NewCertStore()
	store.Replace([]Cert{{Names: []string{"peek.example"}, Default: true, Cert: genCert(t, "peek.example")}})

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	got := make(chan Fingerprint, 1)
	srv := &http.Server{
		ConnContext: ConnContext,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fp, ok := FingerprintFromContext(r.Context())
			if !ok {
				t.Error("no fingerprint in request context")
			}
			got <- fp
			w.WriteHeader(http.StatusNoContent)
		}),
	}
	defer srv.Close()

	tlsLn := tls.NewListener(NewListener(raw), &tls.Config{GetCertificate: store.GetCertificate})
	go srv.Serve(tlsLn)

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "peek.example"},
	}}
	resp, err := client.Get("https://" + raw.Addr().String() + "/probe")
	if err != nil {
		t.Fatalf("request through peeking listener failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d", resp.StatusCode)
	}

	select {
	case fp := <-got:
		if fp.SNI != "peek.example" {
			t.Errorf("SNI = %q", fp.SNI)
		}
		if len(fp.JA3) != 32 {
			t.Errorf("JA3 = %q", fp.JA3)
		}
		if fp.JA4 == "" {
			t.Error("JA4 is empty")
		}
		t.Logf("JA3=%s JA4=%s", fp.JA3, fp.JA4)
	case <-time.After(5 * time.Second):
		t.Fatal("handler never ran")
	}
}

// TestNonTLSBytesAreReplayedIntact guards the replay path for traffic that is
// not a ClientHello at all.
func TestNonTLSBytesAreReplayedIntact(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	ln := NewListener(raw)

	const payload = "GET / HTTP/1.1\r\nHost: plain.example\r\n\r\n"
	go func() {
		c, err := net.Dial("tcp", raw.Addr().String())
		if err != nil {
			return
		}
		defer c.Close()
		io.WriteString(c, payload)
		time.Sleep(200 * time.Millisecond)
	}()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(buf) != payload {
		t.Errorf("replayed %q, want %q", buf, payload)
	}
	if fp := conn.(*Conn).Fingerprint(); fp.JA3 != "" {
		t.Errorf("non-TLS traffic produced a fingerprint: %+v", fp)
	}
}

func TestCAMintsForAnyName(t *testing.T) {
	ca, err := NewCA("heron test authority")
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	leaf, err := ca.Leaf("anything.example")
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	if leaf.Leaf.Subject.CommonName != "anything.example" {
		t.Errorf("common name = %q", leaf.Leaf.Subject.CommonName)
	}
	if len(leaf.Certificate) != 2 {
		t.Errorf("chain has %d certificates, want the leaf and the authority", len(leaf.Certificate))
	}
}

func TestCAVerifiesAgainstItself(t *testing.T) {
	ca, _ := NewCA("heron test authority")
	leaf, err := ca.Leaf("verify.example")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(ca.CertPEM())) {
		t.Fatal("authority PEM did not parse")
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: "verify.example", Roots: pool}); err != nil {
		t.Errorf("a client trusting the authority could not verify the leaf: %v", err)
	}
}

func TestCACachesPerName(t *testing.T) {
	ca, _ := NewCA("heron test authority")
	first, _ := ca.Leaf("cache.example")
	second, _ := ca.Leaf("CACHE.example.")
	if first != second {
		t.Error("the same name was signed twice")
	}
	if ca.Minted() != 1 {
		t.Errorf("minted %d certificates for one name", ca.Minted())
	}
	ca.Leaf("other.example")
	if ca.Minted() != 2 {
		t.Errorf("minted = %d, want 2", ca.Minted())
	}
}

func TestCARoundTripsThroughPEM(t *testing.T) {
	original, _ := NewCA("heron test authority")
	keyPEM, err := original.KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := LoadCA(original.CertPEM(), keyPEM)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if restored.Fingerprint() != original.Fingerprint() {
		t.Error("the restored authority is a different certificate")
	}
	// A leaf from the restored authority must still chain to the original.
	leaf, _ := restored.Leaf("restored.example")
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(original.CertPEM()))
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: "restored.example", Roots: pool}); err != nil {
		t.Errorf("leaf does not chain to the original authority: %v", err)
	}
}

func TestCertStoreFallsBackToTheAuthority(t *testing.T) {
	s := NewCertStore()
	uploaded := genCert(t, "uploaded.example")
	s.Replace([]Cert{{Names: []string{"uploaded.example"}, Cert: uploaded}})

	// With no authority and no certificate marked as the catch-all, an unknown
	// name fails rather than being served someone else's certificate.
	if _, err := s.GetCertificate(&tls.ClientHelloInfo{ServerName: "unknown.example"}); err == nil {
		t.Fatal("an unknown name resolved with no authority installed")
	}

	ca, _ := NewCA("heron test authority")
	s.SetCA(ca)

	got, err := s.GetCertificate(&tls.ClientHelloInfo{ServerName: "unknown.example"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got.Leaf.Subject.CommonName != "unknown.example" {
		t.Errorf("minted for %q", got.Leaf.Subject.CommonName)
	}

	// An uploaded certificate must still win over the authority.
	got, _ = s.GetCertificate(&tls.ClientHelloInfo{ServerName: "uploaded.example"})
	if got != uploaded {
		t.Error("the authority overrode an uploaded certificate")
	}
}

func TestPlainHostsAreNeverMintedFor(t *testing.T) {
	s := NewCertStore()
	ca, _ := NewCA("heron test authority")
	s.SetCA(ca)
	catchAll := genCert(t, "catch.example")
	s.Replace([]Cert{{Names: []string{"catch.example"}, Default: true, Cert: catchAll}})
	s.SetPlainHosts([]string{"plain.example", "*.plain.test"})

	for _, name := range []string{"plain.example", "one.plain.test"} {
		if _, err := s.GetCertificate(&tls.ClientHelloInfo{ServerName: name}); !errors.Is(err, ErrNoCertificate) {
			t.Errorf("%s: got %v, want ErrNoCertificate", name, err)
		}
	}

	// Everything else still mints as before.
	if _, err := s.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example"}); err != nil {
		t.Errorf("a name that is not HTTP only failed: %v", err)
	}
}

func TestPlainHostDoesNotWithdrawAnUploadedCertificate(t *testing.T) {
	s := NewCertStore()
	uploaded := genCert(t, "plain.example")
	s.Replace([]Cert{{Names: []string{"plain.example"}, Cert: uploaded}})
	s.SetPlainHosts([]string{"plain.example"})

	got, err := s.GetCertificate(&tls.ClientHelloInfo{ServerName: "plain.example"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got != uploaded {
		t.Error("an uploaded certificate was withheld")
	}
}

// TestHandshakeWithMintedCertificate is the point of the authority: a client
// that trusts it can complete a handshake for a name nobody uploaded.
func TestHandshakeWithMintedCertificate(t *testing.T) {
	store := NewCertStore()
	ca, _ := NewCA("heron test authority")
	store.SetCA(ca)

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})}
	defer srv.Close()
	go srv.Serve(tls.NewListener(NewListener(raw), &tls.Config{GetCertificate: store.GetCertificate}))

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(ca.CertPEM()))
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "never-uploaded.example"},
	}}

	resp, err := client.Get("https://" + raw.Addr().String() + "/")
	if err != nil {
		t.Fatalf("handshake with a minted certificate failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

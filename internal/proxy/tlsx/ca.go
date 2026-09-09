package tlsx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// Leaf certificates are short-lived: they are minted on demand and cached in
// memory, so there is nothing to rotate.
const (
	leafLifetime = 30 * 24 * time.Hour
	caLifetime   = 10 * 365 * 24 * time.Hour
)

// CA signs certificates for hostnames that have none uploaded.
//
// This is what lets an application be proxied without preparing anything: the
// client sees a certificate for the name it asked for, signed by this
// authority. Trusting the authority once covers every host.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string

	mu     sync.RWMutex
	minted map[string]*tls.Certificate
}

// NewCA generates a fresh authority.
func NewCA(name string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tlsx: generate authority key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name, Organization: []string{"heron"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("tlsx: create authority: %w", err)
	}
	return newCA(der, key)
}

// LoadCA rebuilds an authority from stored PEM.
func LoadCA(certPEM string, keyPEM []byte) (*CA, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("tlsx: authority certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tlsx: parse authority: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("tlsx: authority key is not PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tlsx: parse authority key: %w", err)
	}
	return newCA(cert.Raw, key)
}

func newCA(der []byte, key *ecdsa.PrivateKey) (*CA, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("tlsx: parse authority: %w", err)
	}
	return &CA{
		cert:   cert,
		key:    key,
		pem:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		minted: make(map[string]*tls.Certificate),
	}, nil
}

// CertPEM returns the authority certificate, for installing as trusted.
func (c *CA) CertPEM() string { return c.pem }

// KeyPEM returns the authority private key, for storing.
func (c *CA) KeyPEM() ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(c.key)
	if err != nil {
		return nil, fmt.Errorf("tlsx: marshal authority key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// Fingerprint is the SHA-256 of the authority certificate, for comparing
// against what a client has installed.
func (c *CA) Fingerprint() string {
	sum := sha256.Sum256(c.cert.Raw)
	return hex.EncodeToString(sum[:])
}

// NotAfter is when the authority expires.
func (c *CA) NotAfter() time.Time { return c.cert.NotAfter }

// Leaf returns a certificate for a hostname, minting and caching one on first use.
func (c *CA) Leaf(host string) (*tls.Certificate, error) {
	host = normalizeName(host)
	if host == "" {
		return nil, fmt.Errorf("tlsx: no server name to sign for")
	}

	c.mu.RLock()
	cached, ok := c.minted[host]
	c.mu.RUnlock()
	if ok {
		return cached, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if cached, ok := c.minted[host]; ok {
		return cached, nil
	}
	leaf, err := c.mint(host)
	if err != nil {
		return nil, err
	}
	c.minted[host] = leaf
	return leaf, nil
}

func (c *CA) mint(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tlsx: generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host, Organization: []string{"heron"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(leafLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
		// A wildcard is added for a name that has one, so sibling hosts reuse it.
		if parts := strings.SplitN(host, ".", 2); len(parts) == 2 && strings.Count(host, ".") >= 2 {
			template.DNSNames = append(template.DNSNames, "*."+parts[1])
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("tlsx: sign leaf for %s: %w", host, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("tlsx: parse leaf: %w", err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// Minted reports how many hostnames have been signed for.
func (c *CA) Minted() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.minted)
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("tlsx: serial number: %w", err)
	}
	return serial, nil
}

func normalizeName(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.Trim(host, "[]")
}

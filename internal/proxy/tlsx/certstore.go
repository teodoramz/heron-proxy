package tlsx

import (
	"crypto/tls"
	"errors"
	"strings"
	"sync/atomic"
)

// ErrNoCertificate reports that no certificate matches the requested name.
var ErrNoCertificate = errors.New("tlsx: no certificate for server name")

// Cert is a loaded certificate and the names it serves. A name may be a
// wildcard such as *.example.com.
type Cert struct {
	Names   []string
	Default bool
	Cert    *tls.Certificate
}

type certMap struct {
	exact    map[string]*tls.Certificate
	wildcard map[string]*tls.Certificate
	fallback *tls.Certificate
}

// CertStore resolves certificates by SNI and can be replaced atomically.
//
// An uploaded certificate always wins. When none matches, the store falls back
// to the authority and mints one for the name asked for, so an application can
// be proxied without preparing a certificate first.
type CertStore struct {
	m  atomic.Pointer[certMap]
	ca atomic.Pointer[CA]
}

// NewCertStore returns an empty store.
func NewCertStore() *CertStore {
	s := &CertStore{}
	s.Replace(nil)
	return s
}

// Replace swaps the certificate set. In-flight handshakes keep the old set.
func (s *CertStore) Replace(certs []Cert) {
	m := &certMap{
		exact:    make(map[string]*tls.Certificate, len(certs)),
		wildcard: make(map[string]*tls.Certificate),
	}
	for _, c := range certs {
		if c.Cert == nil {
			continue
		}
		for _, name := range c.Names {
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" {
				continue
			}
			if suffix, ok := strings.CutPrefix(name, "*."); ok {
				m.wildcard[suffix] = c.Cert
			} else {
				m.exact[name] = c.Cert
			}
		}
		// Only an explicit choice becomes the catch-all. Treating the first
		// uploaded certificate as one silently served a wrong-name certificate
		// to every other host.
		if c.Default {
			m.fallback = c.Cert
		}
	}
	s.m.Store(m)
}

// SetCA installs the authority used when nothing else matches.
func (s *CertStore) SetCA(ca *CA) { s.ca.Store(ca) }

// CA returns the installed authority, if any.
func (s *CertStore) CA() *CA { return s.ca.Load() }

// GetCertificate satisfies tls.Config.GetCertificate.
func (s *CertStore) GetCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m := s.m.Load()
	name := strings.ToLower(strings.TrimSuffix(chi.ServerName, "."))

	if c, ok := m.exact[name]; ok {
		return c, nil
	}
	if _, parent, found := strings.Cut(name, "."); found {
		if c, ok := m.wildcard[parent]; ok {
			return c, nil
		}
	}
	// Mint one rather than failing the handshake. A client that trusts the
	// authority sees a valid certificate; one that does not sees a warning,
	// which is the honest result of intercepting the connection.
	//
	// This comes before the explicit catch-all deliberately: a certificate
	// carrying the name that was asked for is better than a valid certificate
	// for some other name.
	if ca := s.ca.Load(); ca != nil && name != "" {
		if leaf, err := ca.Leaf(name); err == nil {
			return leaf, nil
		}
	}
	if m.fallback != nil {
		return m.fallback, nil
	}
	return nil, ErrNoCertificate
}

// Len reports how many distinct names are served.
func (s *CertStore) Len() int {
	m := s.m.Load()
	return len(m.exact) + len(m.wildcard)
}

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
type CertStore struct {
	m atomic.Pointer[certMap]
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
		if c.Default || m.fallback == nil {
			m.fallback = c.Cert
		}
	}
	s.m.Store(m)
}

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

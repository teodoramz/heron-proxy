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

// plainSet holds the names of applications served over HTTP only.
type plainSet struct {
	exact    map[string]bool
	wildcard map[string]bool
}

func (p *plainSet) has(name string) bool {
	if p == nil {
		return false
	}
	if p.exact[name] {
		return true
	}
	_, parent, found := strings.Cut(name, ".")
	return found && p.wildcard[parent]
}

// CertStore resolves certificates by SNI and can be replaced atomically.
//
// An uploaded certificate always wins. When none matches, the store falls back
// to the authority and mints one for the name asked for, so an application can
// be proxied without preparing a certificate first.
type CertStore struct {
	m     atomic.Pointer[certMap]
	ca    atomic.Pointer[CA]
	plain atomic.Pointer[plainSet]
}

// SetPlainHosts marks names that must never be served over TLS. An uploaded
// certificate still wins: naming a host here stops the proxy minting for it,
// it does not withdraw a certificate somebody deliberately installed.
func (s *CertStore) SetPlainHosts(names []string) {
	p := &plainSet{exact: make(map[string]bool), wildcard: make(map[string]bool)}
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		if suffix, ok := strings.CutPrefix(name, "*."); ok {
			p.wildcard[suffix] = true
		} else {
			p.exact[name] = true
		}
	}
	s.plain.Store(p)
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
	// An application marked HTTP only gets nothing beyond an uploaded
	// certificate: no minted leaf, and not the catch-all either.
	if s.plain.Load().has(name) {
		return nil, ErrNoCertificate
	}
	// Before the catch-all deliberately: a certificate carrying the name that
	// was asked for beats a valid certificate for some other name.
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

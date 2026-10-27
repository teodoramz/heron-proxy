package proxy

import (
	"context"
	"testing"

	"github.com/amzteodor/heron/internal/config"
	"github.com/amzteodor/heron/internal/proxy/router"
	"github.com/amzteodor/heron/internal/proxy/tlsx"
	"github.com/amzteodor/heron/internal/proxy/waf"
)

type caSource struct {
	version int64
	ca      *tlsx.CA
}

func (s *caSource) ConfigVersion(context.Context) (int64, error)             { return s.version, nil }
func (s *caSource) ListApps(context.Context) ([]config.App, error)           { return nil, nil }
func (s *caSource) ExclusionRules(context.Context, string) ([]string, error) { return nil, nil }
func (s *caSource) LoadTLSCertificates(context.Context) ([]tlsx.Cert, error) { return nil, nil }
func (s *caSource) EnsureCA(context.Context, string) (*tlsx.CA, error)       { return s.ca, nil }

// Regenerating the authority bumps the configuration version; the next reload
// has to start signing with the new one rather than keep the first it saw.
func TestLoaderPicksUpAReplacedAuthority(t *testing.T) {
	first, _ := tlsx.NewCA("first")
	src := &caSource{version: 1, ca: first}
	certs := tlsx.NewCertStore()
	l := NewLoader(src, router.New(), certs, waf.NewEngine(t.TempDir()), nil)

	if err := l.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if certs.CA() != first {
		t.Fatal("the authority was not installed on the first load")
	}

	// An unrelated reload keeps the same authority, and with it every
	// certificate already minted.
	same, _ := tlsx.LoadCA(first.CertPEM(), mustKeyPEM(t, first))
	src.version, src.ca = 2, same
	if err := l.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if certs.CA() != first {
		t.Error("an unchanged authority was swapped out, dropping its minted certificates")
	}

	second, _ := tlsx.NewCA("second")
	src.version, src.ca = 3, second
	if err := l.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if certs.CA() != second {
		t.Fatal("the proxy kept signing with the replaced authority")
	}
}

func mustKeyPEM(t *testing.T, ca *tlsx.CA) []byte {
	t.Helper()
	key, err := ca.KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

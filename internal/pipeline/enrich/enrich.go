// Package enrich annotates events with geographic and network intelligence.
package enrich

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/oschwald/maxminddb-golang"

	"github.com/amzteodor/proxy-waf/internal/pipeline/event"
)

// Enricher looks up MaxMind City and ASN databases. Either database may be
// absent, in which case the corresponding fields are left empty.
type Enricher struct {
	city *maxminddb.Reader
	asn  *maxminddb.Reader
}

type cityRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

type asnRecord struct {
	Number       uint   `maxminddb:"autonomous_system_number"`
	Organization string `maxminddb:"autonomous_system_organization"`
}

// New opens the databases. Missing paths are not an error; the returned
// Enricher is still usable and simply adds nothing.
func New(cityPath, asnPath string) (*Enricher, error) {
	e := &Enricher{}
	var errs []error

	if cityPath != "" {
		r, err := maxminddb.Open(cityPath)
		if err != nil {
			errs = append(errs, fmt.Errorf("city database: %w", err))
		} else {
			e.city = r
		}
	}
	if asnPath != "" {
		r, err := maxminddb.Open(asnPath)
		if err != nil {
			errs = append(errs, fmt.Errorf("asn database: %w", err))
		} else {
			e.asn = r
		}
	}
	return e, errors.Join(errs...)
}

// Close releases the databases.
func (e *Enricher) Close() error {
	var errs []error
	if e.city != nil {
		errs = append(errs, e.city.Close())
	}
	if e.asn != nil {
		errs = append(errs, e.asn.Close())
	}
	return errors.Join(errs...)
}

// Apply fills country, ASN and organization for the event's client address.
// Private and invalid addresses are skipped.
func (e *Enricher) Apply(ev *event.Event) {
	if e == nil {
		return
	}
	addr := ev.ClientIP
	if !addr.IsValid() || addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() {
		return
	}
	b := addr.As16()
	ip := net.IP(b[:])

	if e.city != nil {
		var rec cityRecord
		if err := e.city.Lookup(ip, &rec); err == nil {
			ev.Country = rec.Country.ISOCode
		}
	}
	if e.asn != nil {
		var rec asnRecord
		if err := e.asn.Lookup(ip, &rec); err == nil {
			ev.ASN = uint32(rec.Number)
			ev.ASOrg = rec.Organization
		}
	}
}

// Lookup returns the enrichment for one address, for the API's IP profile view.
func (e *Enricher) Lookup(addr netip.Addr) (country string, asn uint32, org string) {
	ev := event.Event{ClientIP: addr}
	e.Apply(&ev)
	return ev.Country, ev.ASN, ev.ASOrg
}

package ipinfo

// Domain RDAP lookup — the registrar half of the RDAP protocol. The IP
// path lives in rdap.go; this file reuses its shared helpers
// (firstVCardValue, hasRole, entityName) and the rdap.org redirector,
// pointing them at /domain/{name} instead of /ip/{addr}.
//
// Registrar fields follow the ICANN gTLD RDAP response profile: the
// sponsoring registrar is the entity whose role is "registrar", carrying
// its name in the vCard "fn", its IANA ID in a publicIds entry of type
// "IANA Registrar ID", and its website as an "about" link. Many ccTLDs
// (.hu, several EU ccTLDs) are WHOIS-only or omit these fields — in that
// case the lookup returns nil and callers degrade gracefully.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Registrar is the subset of an RDAP domain response we surface.
type Registrar struct {
	Name   string // vCard "fn" of the registrar entity
	IANAID string // publicIds entry of type "IANA Registrar ID"
	URL    string // registrar "about" link (fallback: vCard "url")
}

// RDAPDomainCache is a process-local cache of domain registrar lookups
// (including misses), mirroring RDAPCache for IPs.
type RDAPDomainCache struct {
	mu     sync.Mutex
	m      map[string]*Registrar
	client *http.Client
}

// NewRDAPDomainCache returns an empty cache with a fresh HTTP client.
func NewRDAPDomainCache() *RDAPDomainCache {
	return &RDAPDomainCache{
		m:      map[string]*Registrar{},
		client: &http.Client{Timeout: 6 * time.Second},
	}
}

// DefaultRDAPDomainCache is the process-wide cache used by the CLI.
var DefaultRDAPDomainCache = NewRDAPDomainCache()

// Lookup returns registrar info for a domain, caching results (including
// misses). Returns nil when the TLD has no RDAP service or exposes no
// registrar entity.
func (c *RDAPDomainCache) Lookup(ctx context.Context, domain string) *Registrar {
	key := normalizeDomain(domain)
	if key == "" {
		return nil
	}

	c.mu.Lock()
	if v, ok := c.m[key]; ok {
		c.mu.Unlock()
		return v
	}
	c.mu.Unlock()

	info := lookupRDAPDomain(ctx, c.client, key)

	c.mu.Lock()
	c.m[key] = info
	c.mu.Unlock()
	return info
}

type rdapDomainResponse struct {
	Entities []rdapEntity `json:"entities"`
}

func lookupRDAPDomain(ctx context.Context, client *http.Client, domain string) *Registrar {
	return lookupRDAPDomainAt(ctx, client, rdapBaseURL, domain)
}

// lookupRDAPDomainAt is the testable form — takes the base URL as a
// parameter so httptest servers can stand in for the RDAP bootstrap.
func lookupRDAPDomainAt(ctx context.Context, client *http.Client, baseURL, domain string) *Registrar {
	domain = normalizeDomain(domain) // idempotent; keeps this entry point correct standalone
	if domain == "" {
		return nil
	}

	c, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(c, "GET", baseURL+"/domain/"+url.PathEscape(domain), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}

	var body rdapDomainResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&body); err != nil {
		return nil
	}
	return registrarFromDomain(&body)
}

func registrarFromDomain(resp *rdapDomainResponse) *Registrar {
	e := findEntityWithRole(resp.Entities, "registrar")
	if e == nil {
		return nil
	}

	r := &Registrar{Name: firstVCardValue(e.VCardArray, "fn")}
	if r.Name == "" {
		r.Name = entityName(*e) // org / handle fallback
	}

	for _, p := range e.PublicIds {
		if strings.EqualFold(strings.TrimSpace(p.Type), "IANA Registrar ID") {
			r.IANAID = strings.TrimSpace(p.Identifier)
			break
		}
	}

	// Prefer the explicit "about" link; some registries only put the URL
	// in the vCard instead.
	for _, l := range e.Links {
		if strings.EqualFold(l.Rel, "about") && strings.TrimSpace(l.Href) != "" {
			r.URL = strings.TrimSpace(l.Href)
			break
		}
	}
	if r.URL == "" {
		r.URL = firstVCardValue(e.VCardArray, "url")
	}

	if r.Name == "" && r.IANAID == "" && r.URL == "" {
		return nil
	}
	return r
}

// findEntityWithRole returns the first entity (depth-first) carrying the
// given role, or nil. Mirrors firstEntityNameWithRole but yields the
// entity itself so callers can read multiple fields off it.
func findEntityWithRole(entities []rdapEntity, role string) *rdapEntity {
	for i := range entities {
		if hasRole(entities[i], role) {
			return &entities[i]
		}
		if e := findEntityWithRole(entities[i].Entities, role); e != nil {
			return e
		}
	}
	return nil
}

// normalizeDomain lowercases and strips any scheme, path, port, or
// trailing dot so callers can pass a bare host, FQDN, or full URL.
func normalizeDomain(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexAny(s, "/:"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSuffix(s, ".")
}

package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type RDAPInfo struct {
	Name       string
	Registry   string
	Country    string
	AbuseEmail string
}

type rdapCache struct {
	mu     sync.Mutex
	m      map[string]*RDAPInfo
	client *http.Client
}

func newRDAPCache() *rdapCache {
	return &rdapCache{
		m:      map[string]*RDAPInfo{},
		client: &http.Client{Timeout: 6 * time.Second},
	}
}

func (c *rdapCache) Lookup(ctx context.Context, ipStr string) *RDAPInfo {
	c.mu.Lock()
	if v, ok := c.m[ipStr]; ok {
		c.mu.Unlock()
		return v
	}
	c.mu.Unlock()

	info := lookupRDAP(ctx, c.client, ipStr)

	c.mu.Lock()
	c.m[ipStr] = info
	c.mu.Unlock()
	return info
}

type rdapIPResponse struct {
	Name     string       `json:"name"`
	Country  string       `json:"country"`
	Port43   string       `json:"port43"`
	Entities []rdapEntity `json:"entities"`
	Links    []rdapLink   `json:"links"`
}

type rdapEntity struct {
	Handle     string          `json:"handle"`
	Roles      []string        `json:"roles"`
	VCardArray json.RawMessage `json:"vcardArray"`
	Entities   []rdapEntity    `json:"entities"`
}

type rdapLink struct {
	Href  string `json:"href"`
	Value string `json:"value"`
}

func lookupRDAP(ctx context.Context, client *http.Client, ipStr string) *RDAPInfo {
	ip := net.ParseIP(ipStr)
	if ip == nil || isPrivateOrSpecial(ip) {
		return nil
	}

	c, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(c, "GET", "https://rdap.org/ip/"+url.PathEscape(ip.String()), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", "netcheck/"+version)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}

	var body rdapIPResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&body); err != nil {
		return nil
	}
	return parseRDAPInfo(&body)
}

func parseRDAPInfo(resp *rdapIPResponse) *RDAPInfo {
	info := &RDAPInfo{
		Name:     strings.TrimSpace(resp.Name),
		Country:  strings.TrimSpace(resp.Country),
		Registry: registryFromRDAP(resp.Port43, resp.Links),
	}
	if org := preferredRDAPOrg(resp.Entities); org != "" {
		info.Name = org
	}
	info.AbuseEmail = firstAbuseEmail(resp.Entities)
	if info.Name == "" && info.Registry == "" && info.Country == "" && info.AbuseEmail == "" {
		return nil
	}
	return info
}

func registryFromRDAP(port43 string, links []rdapLink) string {
	s := strings.ToLower(port43)
	for _, item := range []struct {
		Needle   string
		Registry string
	}{
		{"arin", "arin"},
		{"ripe", "ripe"},
		{"apnic", "apnic"},
		{"lacnic", "lacnic"},
		{"afrinic", "afrinic"},
	} {
		if strings.Contains(s, item.Needle) {
			return item.Registry
		}
	}
	for _, link := range links {
		s = strings.ToLower(link.Href + " " + link.Value)
		for _, item := range []struct {
			Needle   string
			Registry string
		}{
			{"arin", "arin"},
			{"ripe", "ripe"},
			{"apnic", "apnic"},
			{"lacnic", "lacnic"},
			{"afrinic", "afrinic"},
		} {
			if strings.Contains(s, item.Needle) {
				return item.Registry
			}
		}
	}
	return ""
}

func preferredRDAPOrg(entities []rdapEntity) string {
	for _, role := range []string{"registrant", "administrative"} {
		if name := firstEntityNameWithRole(entities, role); name != "" {
			return name
		}
	}
	for _, e := range entities {
		if hasRole(e, "abuse") {
			continue
		}
		if name := entityName(e); name != "" {
			return name
		}
		if name := preferredRDAPOrg(e.Entities); name != "" {
			return name
		}
	}
	return ""
}

func firstEntityNameWithRole(entities []rdapEntity, role string) string {
	for _, e := range entities {
		if hasRole(e, role) {
			if name := entityName(e); name != "" {
				return name
			}
		}
		if name := firstEntityNameWithRole(e.Entities, role); name != "" {
			return name
		}
	}
	return ""
}

func firstAbuseEmail(entities []rdapEntity) string {
	for _, e := range entities {
		if hasRole(e, "abuse") {
			if email := firstVCardValue(e.VCardArray, "email"); email != "" {
				return email
			}
		}
		if email := firstAbuseEmail(e.Entities); email != "" {
			return email
		}
	}
	return ""
}

func hasRole(e rdapEntity, role string) bool {
	for _, r := range e.Roles {
		if strings.EqualFold(r, role) {
			return true
		}
	}
	return false
}

func entityName(e rdapEntity) string {
	for _, field := range []string{"org", "fn"} {
		if v := firstVCardValue(e.VCardArray, field); v != "" {
			return v
		}
	}
	return strings.TrimSpace(e.Handle)
}

func firstVCardValue(raw json.RawMessage, field string) string {
	if len(raw) == 0 {
		return ""
	}
	var card []any
	if err := json.Unmarshal(raw, &card); err != nil || len(card) < 2 {
		return ""
	}
	props, ok := card[1].([]any)
	if !ok {
		return ""
	}
	for _, prop := range props {
		items, ok := prop.([]any)
		if !ok || len(items) < 4 {
			continue
		}
		name, ok := items[0].(string)
		if !ok || !strings.EqualFold(name, field) {
			continue
		}
		if value, ok := items[3].(string); ok {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

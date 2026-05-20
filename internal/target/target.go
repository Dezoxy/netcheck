// Package target handles user-supplied input → canonical URL/hostname conversion.
package target

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Target is a parsed full-URL target used by the full check.
type Target struct {
	Raw    string
	URL    *url.URL
	Host   string
	Port   string
	Scheme string
}

// Parse normalizes a user-supplied string into a Target.
// Missing schemes default to https; bare hostnames get a default port.
func Parse(s string) (*Target, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty target")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("no hostname in %q", s)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return &Target{Raw: s, URL: u, Host: u.Hostname(), Port: port, Scheme: u.Scheme}, nil
}

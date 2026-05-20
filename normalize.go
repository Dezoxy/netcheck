package main

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// normalizeHost strips scheme, path, query, port, surrounding whitespace, and
// surrounding quotes from user input, leaving just the hostname. Used by the
// host-only commands (dns, route) where a full URL would be wrong.
func normalizeHost(input string) (string, error) {
	s := strings.TrimSpace(input)
	s = strings.Trim(s, `"'`)
	if s == "" {
		return "", errors.New("empty input")
	}

	// If it has a scheme, parse as URL and take the hostname.
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", fmt.Errorf("invalid URL: %w", err)
		}
		host := u.Hostname()
		if host == "" {
			return "", fmt.Errorf("no hostname in %q", input)
		}
		return strings.ToLower(host), nil
	}

	// Otherwise, drop anything after the first "/" (path), "?" (query), or "#" (fragment).
	for _, sep := range []string{"/", "?", "#"} {
		if i := strings.Index(s, sep); i >= 0 {
			s = s[:i]
		}
	}
	// Strip a trailing :port if present. IPv6 literals would be wrapped in [],
	// which is rare in this kind of prompt; we handle the bracketed form too.
	if strings.HasPrefix(s, "[") {
		if end := strings.Index(s, "]"); end > 0 {
			s = s[1:end]
		}
	} else if i := strings.LastIndex(s, ":"); i >= 0 && !strings.Contains(s, "::") {
		// Only strip if what follows looks like a port (digits).
		port := s[i+1:]
		if isAllDigits(port) {
			s = s[:i]
		}
	}

	if s == "" {
		return "", fmt.Errorf("could not extract hostname from %q", input)
	}
	return strings.ToLower(s), nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

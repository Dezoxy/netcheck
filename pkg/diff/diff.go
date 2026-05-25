// Package diff compares two netcheck JSON reports and produces a structured
// list of human-meaningful changes — what we'd actually want to know if a
// scheduled scan turned up something new today.
//
// Goals (pragmatic):
//   - Don't be noisy. `took_ms` and `started_at` always differ; suppress.
//   - Prefer set-diff on natural collections (ports, subdomains, hostnames,
//     headers, matches) over recursive field-by-field comparison.
//   - Per-kind handling for the report types we care about (ports, dns,
//     subs, reverse, arch, headers, tech, enum, tls-audit). A generic
//     fallback covers the rest with a sensible default.
//
// Non-goals:
//   - Reconstructing the full JSON tree as a diff. We surface meaningful
//     changes, not every byte.
//   - JSON Patch / RFC 6902 output. The Report struct here is netcheck-
//     specific.
package diff

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Severity tiers the diff entries. Renderers translate these to colours/icons.
type Severity string

const (
	SevInfo Severity = "info" // neutral observation (e.g. new subdomain)
	SevOK   Severity = "ok"   // an improvement (new "pass" grade, port closed)
	SevWarn Severity = "warn" // worth attention (cert closer to expiry, weaker header)
	SevErr  Severity = "err"  // regression (open port, new vulnerability, missing header)
)

// Change is one row in the diff output.
type Change struct {
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
}

// Section groups related changes (e.g. "Ports added", "Headers regressed").
// Empty sections are filtered out before Report is returned.
type Section struct {
	Title   string   `json:"title"`
	Changes []Change `json:"changes,omitempty"`
}

// Report is the top-level diff output.
type Report struct {
	Kind       string    `json:"kind"`             // "ports", "dns", etc., or "mixed" if old/new differ
	Target     string    `json:"target,omitempty"` // host/url, best-effort
	OldStarted time.Time `json:"old_started,omitempty"`
	NewStarted time.Time `json:"new_started,omitempty"`
	Sections   []Section `json:"sections,omitempty"`
	Changed    bool      `json:"changed"`
}

// Diff parses two raw JSON report bodies and returns the structured diff.
// Returns an error when either body fails to parse, but does NOT error on
// kind mismatch — a kind change is itself reported as a change.
func Diff(oldBytes, newBytes []byte) (Report, error) {
	var oldM map[string]any
	if err := json.Unmarshal(oldBytes, &oldM); err != nil {
		return Report{}, fmt.Errorf("parse old: %w", err)
	}
	var newM map[string]any
	if err := json.Unmarshal(newBytes, &newM); err != nil {
		return Report{}, fmt.Errorf("parse new: %w", err)
	}
	return DiffMaps(oldM, newM)
}

// DiffMaps is Diff but takes already-parsed maps. Lets callers (notably
// `netcheck watch`) reuse parsed state without round-tripping through JSON.
func DiffMaps(oldM, newM map[string]any) (Report, error) {
	if oldM == nil || newM == nil {
		return Report{}, errors.New("nil report")
	}
	oldKind, _ := oldM["kind"].(string)
	newKind, _ := newM["kind"].(string)
	rep := Report{
		Kind:       newKind,
		Target:     extractTarget(newM),
		OldStarted: parseTime(oldM["started_at"]),
		NewStarted: parseTime(newM["started_at"]),
	}
	if oldKind != newKind {
		rep.Kind = "mixed"
		rep.Sections = append(rep.Sections, Section{
			Title: "Report kind changed",
			Changes: []Change{{
				Severity: SevWarn,
				Message:  fmt.Sprintf("old=%q  new=%q", oldKind, newKind),
			}},
		})
		rep.Changed = true
		return rep, nil
	}

	switch newKind {
	case "ports":
		rep.Sections = append(rep.Sections, diffPorts(oldM, newM)...)
	case "subs":
		rep.Sections = append(rep.Sections, diffSubs(oldM, newM)...)
	case "reverse":
		rep.Sections = append(rep.Sections, diffReverse(oldM, newM)...)
	case "dns":
		rep.Sections = append(rep.Sections, diffDNS(oldM, newM)...)
	case "headers":
		rep.Sections = append(rep.Sections, diffHeaders(oldM, newM)...)
	case "tech":
		rep.Sections = append(rep.Sections, diffTech(oldM, newM)...)
	case "arch":
		rep.Sections = append(rep.Sections, diffArch(oldM, newM)...)
	case "enum":
		rep.Sections = append(rep.Sections, diffEnum(oldM, newM)...)
	case "tls-audit":
		rep.Sections = append(rep.Sections, diffTLSAudit(oldM, newM)...)
	case "full":
		rep.Sections = append(rep.Sections, diffFull(oldM, newM)...)
	case "takeover":
		rep.Sections = append(rep.Sections, diffTakeover(oldM, newM)...)
	case "ip":
		rep.Sections = append(rep.Sections, diffIP(oldM, newM)...)
	case "route":
		rep.Sections = append(rep.Sections, diffRoute(oldM, newM)...)
	default:
		// Unknown kind — fall back to a top-level scalar field diff. Better
		// than nothing for future report kinds we haven't taught the differ
		// about yet.
		rep.Sections = append(rep.Sections, diffScalars(oldM, newM, "Fields")...)
	}

	rep.Sections = pruneEmpty(rep.Sections)
	for _, s := range rep.Sections {
		if len(s.Changes) > 0 {
			rep.Changed = true
			break
		}
	}
	return rep, nil
}

// =============================================================================
// Per-kind differs
// =============================================================================

func diffPorts(oldM, newM map[string]any) []Section {
	type p struct {
		port    int
		service string
		banner  string
	}
	parsePorts := func(m map[string]any) map[int]p {
		out := map[int]p{}
		arr, _ := m["ports"].([]any)
		for _, e := range arr {
			em, _ := e.(map[string]any)
			port := intField(em, "port")
			if port == 0 {
				continue
			}
			out[port] = p{
				port:    port,
				service: stringField(em, "service"),
				banner:  stringField(em, "banner"),
			}
		}
		return out
	}
	o := parsePorts(oldM)
	n := parsePorts(newM)

	var added, removed, changed []Change
	// New ports — a regression on the security/posture axis (something opened).
	for port, np := range n {
		if _, ok := o[port]; !ok {
			msg := fmt.Sprintf("Port %d opened", port)
			if np.service != "" {
				msg += " (" + np.service + ")"
			}
			if np.banner != "" {
				msg += " — banner: " + np.banner
			}
			added = append(added, Change{Severity: SevErr, Message: msg})
		}
	}
	for port, op := range o {
		if _, ok := n[port]; !ok {
			msg := fmt.Sprintf("Port %d closed", port)
			if op.service != "" {
				msg += " (" + op.service + ")"
			}
			removed = append(removed, Change{Severity: SevOK, Message: msg})
		}
	}
	for port, np := range n {
		op, ok := o[port]
		if !ok {
			continue
		}
		if op.banner != np.banner && (op.banner != "" || np.banner != "") {
			changed = append(changed, Change{
				Severity: SevInfo,
				Message:  fmt.Sprintf("Port %d banner: %q → %q", port, op.banner, np.banner),
			})
		}
	}
	sortByMessage(added)
	sortByMessage(removed)
	sortByMessage(changed)

	return []Section{
		{Title: "Ports opened", Changes: added},
		{Title: "Ports closed", Changes: removed},
		{Title: "Port details changed", Changes: changed},
	}
}

func diffSubs(oldM, newM map[string]any) []Section {
	pickNames := func(m map[string]any) map[string]bool {
		out := map[string]bool{}
		arr, _ := m["subdomains"].([]any)
		for _, e := range arr {
			em, _ := e.(map[string]any)
			if name := stringField(em, "name"); name != "" {
				out[name] = true
			}
		}
		return out
	}
	o := pickNames(oldM)
	n := pickNames(newM)
	var added, removed []Change
	for k := range n {
		if !o[k] {
			added = append(added, Change{Severity: SevInfo, Message: k})
		}
	}
	for k := range o {
		if !n[k] {
			removed = append(removed, Change{Severity: SevInfo, Message: k})
		}
	}
	sortByMessage(added)
	sortByMessage(removed)
	return []Section{
		{Title: "Subdomains added", Changes: added},
		{Title: "Subdomains removed", Changes: removed},
	}
}

func diffReverse(oldM, newM map[string]any) []Section {
	pickNames := func(m map[string]any) map[string]bool {
		out := map[string]bool{}
		arr, _ := m["hostnames"].([]any)
		for _, e := range arr {
			em, _ := e.(map[string]any)
			if name := stringField(em, "name"); name != "" {
				out[name] = true
			}
		}
		return out
	}
	o := pickNames(oldM)
	n := pickNames(newM)
	var added, removed []Change
	for k := range n {
		if !o[k] {
			added = append(added, Change{Severity: SevInfo, Message: k})
		}
	}
	for k := range o {
		if !n[k] {
			removed = append(removed, Change{Severity: SevInfo, Message: k})
		}
	}
	sortByMessage(added)
	sortByMessage(removed)
	return []Section{
		{Title: "Hostnames added", Changes: added},
		{Title: "Hostnames removed", Changes: removed},
	}
}

func diffDNS(oldM, newM map[string]any) []Section {
	// dns has queries[].results[] keyed by qtype + resolver name.
	// We compare per-qtype agreement and per-resolver answer sets.
	type rec struct {
		qtype    string
		resolver string
		records  []string
	}
	flatten := func(m map[string]any) map[string]rec {
		out := map[string]rec{}
		queries, _ := m["queries"].([]any)
		for _, q := range queries {
			qm, _ := q.(map[string]any)
			qtype := stringField(qm, "qtype")
			results, _ := qm["results"].([]any)
			for _, r := range results {
				rm, _ := r.(map[string]any)
				name := stringField(rm, "name")
				if name == "" {
					continue
				}
				var recs []string
				if rs, ok := rm["records"].([]any); ok {
					for _, v := range rs {
						if s, ok := v.(string); ok {
							recs = append(recs, s)
						}
					}
				}
				sort.Strings(recs)
				out[qtype+"|"+name] = rec{qtype: qtype, resolver: name, records: recs}
			}
		}
		return out
	}
	o := flatten(oldM)
	n := flatten(newM)
	var changes []Change
	keys := map[string]bool{}
	for k := range o {
		keys[k] = true
	}
	for k := range n {
		keys[k] = true
	}
	var sortedKeys []string
	for k := range keys {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)
	for _, k := range sortedKeys {
		or, ok := o[k]
		nr, ok2 := n[k]
		switch {
		case !ok && ok2:
			changes = append(changes, Change{
				Severity: SevInfo,
				Message:  fmt.Sprintf("[%s] %s: new resolver returning %v", nr.qtype, nr.resolver, nr.records),
			})
		case ok && !ok2:
			changes = append(changes, Change{
				Severity: SevWarn,
				Message:  fmt.Sprintf("[%s] %s: resolver no longer present", or.qtype, or.resolver),
			})
		case strings.Join(or.records, ",") != strings.Join(nr.records, ","):
			changes = append(changes, Change{
				Severity: SevWarn,
				Message:  fmt.Sprintf("[%s] %s: %v → %v", nr.qtype, nr.resolver, or.records, nr.records),
			})
		}
	}
	return []Section{{Title: "DNS resolver answers", Changes: changes}}
}

func diffHeaders(oldM, newM map[string]any) []Section {
	type f struct {
		name    string
		grade   string
		value   string
		comment string
	}
	pick := func(m map[string]any) map[string]f {
		out := map[string]f{}
		arr, _ := m["findings"].([]any)
		for _, e := range arr {
			em, _ := e.(map[string]any)
			name := stringField(em, "name")
			if name == "" {
				continue
			}
			out[name] = f{
				name:    name,
				grade:   stringField(em, "grade"),
				value:   stringField(em, "value"),
				comment: stringField(em, "comment"),
			}
		}
		return out
	}
	o := pick(oldM)
	n := pick(newM)
	var changes []Change
	keys := map[string]bool{}
	for k := range o {
		keys[k] = true
	}
	for k := range n {
		keys[k] = true
	}
	var sortedKeys []string
	for k := range keys {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)
	for _, k := range sortedKeys {
		of, in := o[k]
		nf, nn := n[k]
		switch {
		case !in && nn:
			changes = append(changes, Change{Severity: severityForGrade(nf.grade),
				Message: fmt.Sprintf("%s: new (%s)", k, nf.grade)})
		case in && !nn:
			changes = append(changes, Change{Severity: SevWarn,
				Message: fmt.Sprintf("%s: no longer reported", k)})
		case of.grade != nf.grade:
			sev := SevInfo
			if isWorseGrade(of.grade, nf.grade) {
				sev = SevErr
			} else if isBetterGrade(of.grade, nf.grade) {
				sev = SevOK
			}
			changes = append(changes, Change{Severity: sev,
				Message: fmt.Sprintf("%s: grade %s → %s", k, of.grade, nf.grade)})
		case of.value != nf.value:
			changes = append(changes, Change{Severity: SevInfo,
				Message: fmt.Sprintf("%s: value changed", k)})
		}
	}
	return []Section{{Title: "Security headers", Changes: changes}}
}

func diffTech(oldM, newM map[string]any) []Section {
	pick := func(m map[string]any) map[string]string {
		out := map[string]string{}
		arr, _ := m["matches"].([]any)
		for _, e := range arr {
			em, _ := e.(map[string]any)
			name := stringField(em, "name")
			if name == "" {
				continue
			}
			out[name] = stringField(em, "version")
		}
		return out
	}
	o := pick(oldM)
	n := pick(newM)
	var added, removed, changed []Change
	for k, nv := range n {
		ov, ok := o[k]
		if !ok {
			msg := k
			if nv != "" {
				msg += " " + nv
			}
			added = append(added, Change{Severity: SevInfo, Message: msg})
		} else if ov != nv {
			changed = append(changed, Change{Severity: SevInfo,
				Message: fmt.Sprintf("%s: %s → %s", k, ov, nv)})
		}
	}
	for k := range o {
		if _, ok := n[k]; !ok {
			removed = append(removed, Change{Severity: SevInfo, Message: k})
		}
	}
	sortByMessage(added)
	sortByMessage(removed)
	sortByMessage(changed)
	return []Section{
		{Title: "Tech detected", Changes: added},
		{Title: "Tech no longer detected", Changes: removed},
		{Title: "Tech version changed", Changes: changed},
	}
}

func diffArch(oldM, newM map[string]any) []Section {
	var changes []Change
	if ot, nt := intField(oldM, "total"), intField(newM, "total"); ot != nt {
		sev := SevInfo
		if nt > ot {
			sev = SevInfo
		}
		changes = append(changes, Change{Severity: sev,
			Message: fmt.Sprintf("Total snapshots: %d → %d (%+d)", ot, nt, nt-ot)})
	}
	if olast, nlast := stringField(oldM, "last"), stringField(newM, "last"); olast != nlast {
		changes = append(changes, Change{Severity: SevInfo,
			Message: fmt.Sprintf("Most-recent snapshot: %s → %s", olast, nlast)})
	}
	return []Section{{Title: "Wayback", Changes: changes}}
}

func diffEnum(oldM, newM map[string]any) []Section {
	type f struct {
		url      string
		status   int
		category string
	}
	pick := func(m map[string]any) map[string]f {
		out := map[string]f{}
		arr, _ := m["findings"].([]any)
		for _, e := range arr {
			em, _ := e.(map[string]any)
			path := stringField(em, "path")
			if path == "" {
				continue
			}
			out[path] = f{
				url:      stringField(em, "url"),
				status:   intField(em, "status"),
				category: stringField(em, "category"),
			}
		}
		return out
	}
	o := pick(oldM)
	n := pick(newM)
	var added, removed, changed []Change
	for k, nv := range n {
		ov, ok := o[k]
		if !ok {
			added = append(added, Change{Severity: SevInfo,
				Message: fmt.Sprintf("%s [%d %s]", k, nv.status, nv.category)})
		} else if ov.status != nv.status || ov.category != nv.category {
			changed = append(changed, Change{Severity: SevInfo,
				Message: fmt.Sprintf("%s: %d/%s → %d/%s", k, ov.status, ov.category, nv.status, nv.category)})
		}
	}
	for k := range o {
		if _, ok := n[k]; !ok {
			removed = append(removed, Change{Severity: SevInfo, Message: k})
		}
	}
	sortByMessage(added)
	sortByMessage(removed)
	sortByMessage(changed)
	return []Section{
		{Title: "Paths added", Changes: added},
		{Title: "Paths removed", Changes: removed},
		{Title: "Path status changed", Changes: changed},
	}
}

func diffTLSAudit(oldM, newM map[string]any) []Section {
	var changes []Change
	oldCert, _ := oldM["cert"].(map[string]any)
	newCert, _ := newM["cert"].(map[string]any)
	if oldCert != nil && newCert != nil {
		if oi, ni := stringField(oldCert, "issuer"), stringField(newCert, "issuer"); oi != ni {
			changes = append(changes, Change{Severity: SevWarn,
				Message: fmt.Sprintf("Certificate issuer: %s → %s", oi, ni)})
		}
		if ona, nna := stringField(oldCert, "not_after"), stringField(newCert, "not_after"); ona != nna {
			changes = append(changes, Change{Severity: SevInfo,
				Message: fmt.Sprintf("Certificate not_after: %s → %s", ona, nna)})
		}
		if od, nd := intField(oldCert, "days_remaining"), intField(newCert, "days_remaining"); nd < 30 && od >= 30 {
			changes = append(changes, Change{Severity: SevWarn,
				Message: fmt.Sprintf("Certificate now <30 days from expiry (%d days)", nd)})
		}
	}
	// New findings → regressions; resolved findings → improvements.
	oldF := pickStrings(oldM, "findings", "title")
	newF := pickStrings(newM, "findings", "title")
	for f := range newF {
		if !oldF[f] {
			changes = append(changes, Change{Severity: SevErr, Message: "New finding: " + f})
		}
	}
	for f := range oldF {
		if !newF[f] {
			changes = append(changes, Change{Severity: SevOK, Message: "Resolved finding: " + f})
		}
	}
	return []Section{{Title: "TLS audit", Changes: changes}}
}

func diffFull(oldM, newM map[string]any) []Section {
	var changes []Change
	if oo, no := boolField(oldM, "ok"), boolField(newM, "ok"); oo != no {
		sev := SevErr
		if no {
			sev = SevOK
		}
		changes = append(changes, Change{Severity: sev,
			Message: fmt.Sprintf("Overall ok: %v → %v", oo, no)})
	}
	oldHTTP, _ := oldM["http"].(map[string]any)
	newHTTP, _ := newM["http"].(map[string]any)
	if oldHTTP != nil && newHTTP != nil {
		if os, ns := intField(oldHTTP, "status"), intField(newHTTP, "status"); os != ns {
			sev := SevWarn
			if ns >= 200 && ns < 400 {
				sev = SevInfo
			}
			if ns >= 500 {
				sev = SevErr
			}
			changes = append(changes, Change{Severity: sev,
				Message: fmt.Sprintf("HTTP status: %d → %d", os, ns)})
		}
		if of, nf := stringField(oldHTTP, "final_url"), stringField(newHTTP, "final_url"); of != nf {
			changes = append(changes, Change{Severity: SevInfo,
				Message: fmt.Sprintf("Final URL: %s → %s", of, nf)})
		}
	}
	return []Section{{Title: "Full check", Changes: changes}}
}

func diffTakeover(oldM, newM map[string]any) []Section {
	type f struct {
		cname   string
		verdict string
	}
	pick := func(m map[string]any) map[string]f {
		out := map[string]f{}
		arr, _ := m["findings"].([]any)
		for _, e := range arr {
			em, _ := e.(map[string]any)
			cname := stringField(em, "cname")
			if cname == "" {
				continue
			}
			out[cname] = f{cname: cname, verdict: stringField(em, "verdict")}
		}
		return out
	}
	o := pick(oldM)
	n := pick(newM)
	var changes []Change
	for k, nf := range n {
		of, ok := o[k]
		if !ok {
			sev := SevInfo
			if nf.verdict == "vulnerable" {
				sev = SevErr
			}
			changes = append(changes, Change{Severity: sev,
				Message: fmt.Sprintf("%s: new (%s)", k, nf.verdict)})
		} else if of.verdict != nf.verdict {
			sev := SevInfo
			if nf.verdict == "vulnerable" {
				sev = SevErr
			} else if of.verdict == "vulnerable" {
				sev = SevOK
			}
			changes = append(changes, Change{Severity: sev,
				Message: fmt.Sprintf("%s: %s → %s", k, of.verdict, nf.verdict)})
		}
	}
	for k, of := range o {
		if _, ok := n[k]; !ok {
			changes = append(changes, Change{Severity: SevInfo,
				Message: fmt.Sprintf("%s: removed (was %s)", k, of.verdict)})
		}
	}
	sortByMessage(changes)
	return []Section{{Title: "Subdomain takeover", Changes: changes}}
}

func diffIP(oldM, newM map[string]any) []Section {
	// Per-IP ASN/CDN comparison. Keyed by ip.
	pick := func(m map[string]any) map[string]map[string]any {
		out := map[string]map[string]any{}
		arr, _ := m["details"].([]any)
		for _, e := range arr {
			em, _ := e.(map[string]any)
			ip := stringField(em, "ip")
			if ip != "" {
				out[ip] = em
			}
		}
		return out
	}
	o := pick(oldM)
	n := pick(newM)
	var changes []Change
	for ip, nd := range n {
		od, ok := o[ip]
		if !ok {
			changes = append(changes, Change{Severity: SevInfo,
				Message: fmt.Sprintf("%s: new IP in result", ip)})
			continue
		}
		oldASN, _ := od["asn"].(map[string]any)
		newASN, _ := nd["asn"].(map[string]any)
		if oldASN != nil && newASN != nil {
			if oa, na := stringField(oldASN, "asn"), stringField(newASN, "asn"); oa != na {
				changes = append(changes, Change{Severity: SevWarn,
					Message: fmt.Sprintf("%s: ASN %s → %s", ip, oa, na)})
			}
		}
		oldCDN, _ := od["cdn"].(map[string]any)
		newCDN, _ := nd["cdn"].(map[string]any)
		op := ""
		np := ""
		if oldCDN != nil {
			op = stringField(oldCDN, "provider")
		}
		if newCDN != nil {
			np = stringField(newCDN, "provider")
		}
		if op != np {
			changes = append(changes, Change{Severity: SevInfo,
				Message: fmt.Sprintf("%s: CDN %q → %q", ip, op, np)})
		}
	}
	for ip := range o {
		if _, ok := n[ip]; !ok {
			changes = append(changes, Change{Severity: SevInfo,
				Message: fmt.Sprintf("%s: removed from result", ip)})
		}
	}
	sortByMessage(changes)
	return []Section{{Title: "IP details", Changes: changes}}
}

func diffRoute(oldM, newM map[string]any) []Section {
	// Route is timing-noisy by design — only surface coarse outcomes:
	// reached/not, hop count, ASN at the final hop.
	var changes []Change
	if or, nr := boolField(oldM, "reached"), boolField(newM, "reached"); or != nr {
		sev := SevErr
		if nr {
			sev = SevOK
		}
		changes = append(changes, Change{Severity: sev,
			Message: fmt.Sprintf("Reached destination: %v → %v", or, nr)})
	}
	oldHops, _ := oldM["hops"].([]any)
	newHops, _ := newM["hops"].([]any)
	if len(oldHops) != len(newHops) {
		changes = append(changes, Change{Severity: SevInfo,
			Message: fmt.Sprintf("Hop count: %d → %d", len(oldHops), len(newHops))})
	}
	return []Section{{Title: "Route", Changes: changes}}
}

// =============================================================================
// Generic helpers
// =============================================================================

// diffScalars is the fallback for unknown kinds. Walks the top-level fields
// (skipping ones we know are noise) and reports any scalar-value differences.
// Won't recurse into nested objects/arrays — those need per-kind handling.
func diffScalars(oldM, newM map[string]any, title string) []Section {
	ignored := map[string]bool{
		"took_ms": true, "started_at": true, "netcheck_version": true,
	}
	keys := map[string]bool{}
	for k := range oldM {
		keys[k] = true
	}
	for k := range newM {
		keys[k] = true
	}
	var sortedKeys []string
	for k := range keys {
		if !ignored[k] {
			sortedKeys = append(sortedKeys, k)
		}
	}
	sort.Strings(sortedKeys)
	var changes []Change
	for _, k := range sortedKeys {
		ov, in := oldM[k]
		nv, nn := newM[k]
		// Only diff scalars at the top level.
		if !isScalar(ov) || !isScalar(nv) {
			continue
		}
		switch {
		case !in && nn:
			changes = append(changes, Change{Severity: SevInfo,
				Message: fmt.Sprintf("%s: added (%v)", k, nv)})
		case in && !nn:
			changes = append(changes, Change{Severity: SevInfo,
				Message: fmt.Sprintf("%s: removed (was %v)", k, ov)})
		case fmt.Sprintf("%v", ov) != fmt.Sprintf("%v", nv):
			changes = append(changes, Change{Severity: SevInfo,
				Message: fmt.Sprintf("%s: %v → %v", k, ov, nv)})
		}
	}
	return []Section{{Title: title, Changes: changes}}
}

func extractTarget(m map[string]any) string {
	// Try the common identity fields in the order they appear across kinds.
	for _, k := range []string{"host", "domain", "url", "base_url", "target", "ip"} {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	// Full check nests under target.{raw,host}.
	if t, ok := m["target"].(map[string]any); ok {
		if r := stringField(t, "raw"); r != "" {
			return r
		}
		if h := stringField(t, "host"); h != "" {
			return h
		}
	}
	return ""
}

func stringField(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func intField(m map[string]any, key string) int {
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	}
	return 0
}

func boolField(m map[string]any, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

func parseTime(v any) time.Time {
	s, _ := v.(string)
	if s == "" {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

// pickStrings extracts a set of strings from each element of arr-of-objects.
// e.g. pickStrings(m, "findings", "title") returns the set of finding.title.
func pickStrings(m map[string]any, arrayKey, fieldKey string) map[string]bool {
	out := map[string]bool{}
	arr, _ := m[arrayKey].([]any)
	for _, e := range arr {
		em, _ := e.(map[string]any)
		if s := stringField(em, fieldKey); s != "" {
			out[s] = true
		}
	}
	return out
}

func isScalar(v any) bool {
	switch v.(type) {
	case nil, bool, float64, int, int64, string:
		return true
	}
	return false
}

func sortByMessage(c []Change) {
	sort.Slice(c, func(i, j int) bool { return c[i].Message < c[j].Message })
}

func pruneEmpty(secs []Section) []Section {
	out := secs[:0]
	for _, s := range secs {
		if len(s.Changes) > 0 {
			out = append(out, s)
		}
	}
	return out
}

// gradeRank turns a header grade into an ordering. Bigger = better.
func gradeRank(g string) int {
	switch g {
	case "pass":
		return 3
	case "info":
		return 2
	case "weak":
		return 1
	case "missing":
		return 0
	}
	return -1
}

func severityForGrade(g string) Severity {
	switch g {
	case "pass":
		return SevOK
	case "missing", "weak":
		return SevWarn
	}
	return SevInfo
}

func isBetterGrade(oldG, newG string) bool { return gradeRank(newG) > gradeRank(oldG) }
func isWorseGrade(oldG, newG string) bool  { return gradeRank(newG) < gradeRank(oldG) }

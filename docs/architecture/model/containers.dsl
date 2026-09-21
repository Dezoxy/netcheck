// The system in scope and its containers. A C4 container is a runtime unit, not
// a Docker container: the CLI and the local web server are two modes of the one
// Go binary, and both call the same probe engine in pkg/.
// Groups mark where each part runs; the security view relies on them.

netcheck = softwareSystem "Netcheck" "Explains what happens between the user's machine and a target: DNS, TCP, TLS, HTTP, routing, IP ownership and resolver disagreement, plus optional authorised active scans." {

    group "Browser" {
        workbench = container "Web Workbench" "Single-page app and PWA: runs checks, streams scan progress, compares and saves reports. The service worker caches the app shell only, never /api/." "React 19, TypeScript, Vite" "Layer Interface,Web UI"
    }

    group "Host running netcheck" {
        cli = container "CLI" "Runs one diagnostic or scan per invocation, an interval watch, or an interactive menu; prints text, JSON, Markdown or HTML." "Go, static binary (CGO disabled)" "Layer Interface"
        appServer = container "Local Web Server" "netcheck app: serves the embedded workbench and a JSON/SSE API over the same probe engine as the CLI. Binds 127.0.0.1:8787 by default, 0.0.0.0:8787 in the container image; requires a token when reachable beyond this machine." "Go net/http, same binary" "Layer Engine,Unauthenticated"
        savedReports = container "Saved Reports" "One JSON file per saved report under $XDG_DATA_HOME or ~/.config, in netcheck/saved-reports; directory 0700, files 0600." "JSON files" "Layer Data,Storage"
    }
}

// Users
user -> netcheck.cli "Runs diagnostics and authorised scans with" "Terminal" "Person"
user -> netcheck.workbench "Runs diagnostics and reviews reports in" "Web browser" "Person"

// Web Workbench
netcheck.workbench -> netcheck.appServer "Loads the app and requests checks, scans and saved reports from" "HTTP/JSON and SSE" "Layer Interface"
netcheck.workbench -> googleFonts "Loads web fonts from" "HTTPS" "Layer Interface"

// Published instance only (see the Published deployment): the browser reaches
// the server through Cloudflare Access, which enforces sign-in first; netcheck
// then requires its own token (decision 4).
user -> cfAccess "Signs in to the published workbench through" "HTTPS, identity provider" "Person"
netcheck.workbench -> cfAccess "Sends requests for the published instance through" "HTTPS" "Layer Interface"
accessToServer = cfAccess -> netcheck.appServer "Forwards signed-in requests to" "Cloudflare Tunnel, then a reverse proxy"

// Local Web Server
netcheck.appServer -> netcheck.savedReports "Reads, writes and deletes saved reports in" "Local filesystem" "Layer Engine"
netcheck.appServer -> targets "Probes and, with authorisation, actively scans" "DNS, TCP, UDP, TLS, HTTP(S), system traceroute" "Layer Engine"
netcheck.appServer -> resolvers "Compares answers from" "DNS over UDP/TCP, DoT, DoH" "Layer Engine"
netcheck.appServer -> registries "Looks up IP and domain ownership from" "RDAP over HTTPS, WHOIS over TCP 43, DNS TXT" "Layer Engine"
netcheck.appServer -> reconServices "Collects subdomains, co-hosted domains and archived URLs from" "HTTPS/JSON" "Layer Engine"

// CLI (same probe engine, same external dependencies)
netcheck.cli -> targets "Probes and, with authorisation, actively scans" "DNS, TCP, UDP, TLS, HTTP(S), system traceroute" "Layer Interface"
netcheck.cli -> resolvers "Compares answers from" "DNS over UDP/TCP, DoT, DoH" "Layer Interface"
netcheck.cli -> registries "Looks up IP and domain ownership from" "RDAP over HTTPS, WHOIS over TCP 43, DNS TXT" "Layer Interface"
netcheck.cli -> reconServices "Collects subdomains, co-hosted domains and archived URLs from" "HTTPS/JSON" "Layer Interface"

// Any open page can still send the request; the server refuses it
// (cmd/app_security.go). Drawn so the Security view shows the control.
otherSites -> netcheck.appServer "Sends cross-site requests, which are refused by" "HTTP from the user's browser; Sec-Fetch-Site, Origin and Host checked" "Inbound across trust boundary"

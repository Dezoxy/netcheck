// People and software systems outside the system in scope.
// The system in scope (Netcheck) is defined in containers.dsl.

user = person "Netcheck User" "Developer, SRE or network engineer diagnosing hosts they operate or are authorised to test."

targets = softwareSystem "Target Hosts" "Hosts and URLs the user names. Receive DNS lookups, TCP/UDP connects, TLS handshakes and HTTP(S) requests; port scans, TLS audits, path enumeration and takeover checks only with explicit authorisation." "External"
resolvers = softwareSystem "DNS Resolvers" "The system resolver plus Cloudflare 1.1.1.1, Google 8.8.8.8 and Quad9 9.9.9.9 by default; DoT and DoH resolvers only from config or flags." "External"
registries = softwareSystem "Internet Registries" "RDAP via rdap.org, WHOIS on TCP 43 (whois.iana.org, then the TLD's server) and Team Cymru IP-to-ASN over DNS." "External"
reconServices = softwareSystem "Passive Recon Services" "Certificate Transparency search (crt.sh, Cert Spotter), reverse IP (HackerTarget; Shodan only when an API key is configured) and the Wayback Machine CDX API." "External"
googleFonts = softwareSystem "Google Fonts" "Serves the Inter and JetBrains Mono web fonts that the workbench's index.html requests." "External"

// Not a dependency: any page open in the same browser. Modelled because the
// local web server accepts its requests (see the Security view).
otherSites = softwareSystem "Other Websites" "Any web page open in the same browser as the workbench." "External"

## Glossary

| Term | Meaning in netcheck |
|---|---|
| Active check | A check that sends traffic a target could treat as an attack: port scan, TLS audit, path enumeration, takeover check. Requires `--i-have-authorization`, `NETCHECK_AUTHORIZED` or `i_have_authorization` in the API body. |
| Passive check | A check that only looks things up or makes an ordinary request: DNS, headers, IP ownership, Certificate Transparency. |
| ASN | Autonomous System Number: identifies the network operator an IP address belongs to. netcheck resolves it through Team Cymru over DNS. |
| Certificate Transparency (CT) | Public logs of issued TLS certificates. netcheck searches them (crt.sh, Cert Spotter) to find subdomains. |
| DoH / DoT | DNS over HTTPS / DNS over TLS: encrypted DNS transports, used only for resolvers set in config or flags. |
| RDAP | Registration Data Access Protocol: the JSON successor to WHOIS for domain and IP registration data. |
| WHOIS | The older plain-text registration lookup on TCP port 43; netcheck falls back to it. |
| SSE | Server-sent events: the one-way HTTP stream the workbench uses for scan progress and live events. |
| PWA | Progressive web app: the workbench can be installed, and its service worker caches the app shell (never `/api/`). |
| Saved report | A check result the workbench asked the server to keep, stored as one JSON file. |
| Subdomain takeover | A dangling DNS record (usually a CNAME) pointing at a deprovisioned third-party resource that someone else could claim. |
| Workbench | The React web UI served by `netcheck app`. |

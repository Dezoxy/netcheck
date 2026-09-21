## Security architecture

netcheck has no accounts, secrets store or hosted service (C-06). Its security
questions are about the user's own machine: who can make it send traffic, and
what it sends. The rules for users are in the
[responsible-use policy](https://github.com/Dezoxy/netcheck/blob/main/docs/ETHICS.md);
this page covers how the software enforces them and where it does not. The
Security view is on the Scope page.

### Trust boundaries

| Boundary | What crosses it | Control today |
|---|---|---|
| User → CLI | Commands typed or scripted by the user | The operating system's user account. Anything the user can run, netcheck runs. |
| Browser → local web server | HTTP/JSON and SSE requests to `127.0.0.1:8787` | Loopback bind only (decision 3). No authentication, `Origin`, `Host` or `Content-Type` check, so any page in the same browser gets through (RISK-001). |
| netcheck → targets and lookup services | DNS, TCP, UDP, TLS and HTTP(S) from the user's source IP | Active checks need authorisation (decision 2). Passive checks are unrestricted by design. |
| Container host → container | Requests to the published port | Whatever the `docker run -p` mapping allows. The image binds `0.0.0.0:8787`. |

### The authorisation gate

Active checks (`tls`, `takeover`, `ports`, `enum`, `audit --active`) run only
with `--i-have-authorization`, `NETCHECK_AUTHORIZED` or, through the API,
`"i_have_authorization": true` in the request body (C-05, decision 2). Without
it the CLI exits 2 and the API answers 403; both behaviours are tested
(QA-04).

The policy is explicit that the flag is **not a security boundary**: anyone
can pass it. It is a deliberation boundary, a point where a person stops and
checks. That is why RISK-001 matters beyond the scan itself: a web page
sending the flag skips the deliberation the gate exists for.

### What netcheck sends and keeps

- No telemetry; nothing is reported to the maintainers (P-04, QA-03).
- Queried names and addresses go to the resolvers, registries and passive
  recon services the chosen check uses, and the workbench loads Google Fonts
  on every start (TD-003).
- The optional Shodan API key lives in the local config file.
- Saved reports are local JSON files, directory `0700`, files `0600`.

### Open items

- RISK-001: cross-site requests and DNS rebinding against the local server.
- RISK-002: the policy promises probe rate limiting that the API does not
  enforce.

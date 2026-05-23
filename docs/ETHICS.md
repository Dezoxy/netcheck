# Ethics and authorization

Starting with **v1.5**, netcheck ships a small suite of *active* network probes:

- `netcheck ports <host>` — TCP connect scan against a port list
- `netcheck tls <host>` — handshake the target across every protocol / cipher
- `netcheck enum <url>` — request paths from a wordlist
- `netcheck takeover <domain>` — fingerprint dangling CNAME records

These differ from every command shipped through v1.4: they send traffic *to the target*. That makes them subject to law and contract in ways the earlier passive commands aren't.

This document explains what "authorized" means in this project, why netcheck refuses to run these commands without an explicit opt-in, and how to do this safely.

---

## TL;DR

> **Do not run active scans against systems you do not own and do not have written permission to test.** This is not a guideline. In most countries it is a criminal offense, and netcheck is not a defence.

If you can answer "yes" to any of the following, you are authorized:

- You own the target outright (your domain, your server, your network).
- You have written authorization from the target's owner — an engagement letter, a signed scope-of-work, an email saying "go ahead" from the right person.
- The target is enrolled in a public bug bounty program (HackerOne, Bugcrowd, Intigriti, etc.) **and** what you're doing is within the program's scope.
- You are testing infrastructure controlled by your employer **and** your employer has authorized the work in writing.

Anything else — "I'm curious", "they shouldn't have left it open", "I'm just looking" — is not authorization.

---

## How netcheck enforces this

Every v1.5 active-scanning command refuses to run unless you confirm authorization. Two equivalent ways to confirm:

```bash
# per-invocation flag
netcheck ports --i-have-authorization example.com

# environment variable for the whole session
export NETCHECK_AUTHORIZED=1
netcheck ports example.com
```

Without either, the command exits with code `2` and prints a refusal banner pointing back at this document.

The flag is intentionally verbose. Typing `--i-have-authorization` is meant to make you stop and check, the same way `rm -rf` should make you stop and check. It is not a security boundary — anyone can pass the flag — but it is a *deliberation* boundary, and that is the goal.

If you find yourself adding `--i-have-authorization` to a script by reflex, stop and review whether you actually have authorization for everything that script will hit.

---

## The legal landscape (not legal advice)

> netcheck's author is a developer, not a lawyer. This summary is to make you aware of the categories of law that apply; consult a lawyer for your jurisdiction and situation.

Unauthorized active probing is criminal in most jurisdictions netcheck users are likely to be in. A non-exhaustive list of statutes you should know about:

- **United States** — Computer Fraud and Abuse Act (18 U.S.C. §1030). Accessing a computer "without authorization" or "exceeding authorized access" is a federal offense. Port scanning has been argued in court both ways; the cheapest defence is "don't do it without permission."
- **United Kingdom** — Computer Misuse Act 1990 §1 (unauthorized access). Conviction can carry imprisonment.
- **Germany** — Strafgesetzbuch §202c ("Hackerparagraph"). Preparation of computer offenses is itself an offense; merely possessing or distributing tools intended for unauthorized access can be charged, depending on intent. This is why some German distributions ship security tools differently.
- **Hungary** — Btk. §423 (information system breach). Unauthorized access to an information system is punishable by up to two years imprisonment.
- **European Union** — Directive 2013/40/EU on attacks against information systems. Member states have implementing statutes broadly aligned with the above.
- **Australia** — Criminal Code Act 1995 Part 10.7 (computer offences).
- **Canada** — Criminal Code §342.1 (unauthorized use of computer).

In addition to criminal exposure: the GDPR (and equivalent regimes) treats personal data exposed during a scan as data the scanner has now processed. If you scan an EU service without authorization and your scan retrieves anything that could be personal data, you have a separate Article 6 problem on top of any criminal exposure.

Bug bounty programs typically provide narrow contractual authorization within the program's scope. **Read the scope carefully**: out-of-scope assets, denial-of-service testing, and social engineering are usually excluded even when other testing is permitted.

---

## What "passive" vs "active" means in netcheck

| Command | Tier | Talks to target? | Ethics gate? |
|---|---|---|---|
| `netcheck <target>` | full check | yes (1 GET) | no — same as a browser visit |
| `netcheck dns <host>` | passive | no (resolvers only) | no |
| `netcheck route <host>` | passive | yes (ICMP traceroute) | no — common diagnostic |
| `netcheck ip <ip>` | passive | no (RDAP / WHOIS) | no |
| `netcheck headers <url>` | v1.4 passive | yes (1 GET) | no — same as a browser visit |
| `netcheck tech <url>` | v1.4 passive | yes (1 GET) | no — same as a browser visit |
| `netcheck subs <domain>` | v1.4 passive | no (CT log aggregators) | no |
| `netcheck reverse <ip>` | v1.4 passive | no (PTR + APIs) | no |
| `netcheck arch <domain>` | v1.4 passive | no (archive.org) | no |
| `netcheck ports <host>` | **v1.5 active** | yes (TCP handshakes per port) | **yes** |
| `netcheck tls <host>` | **v1.5 active** | yes (TLS handshakes per protocol/cipher) | **yes** |
| `netcheck enum <url>` | **v1.5 active** | yes (HTTP request per path) | **yes** |
| `netcheck takeover <domain>` | **v1.5 active** | DNS only — but the *output* is exploitation-actionable | **yes** |

`takeover` is a borderline case. The CNAME lookup itself is benign — it's identical to `dig`. The reason it sits behind the gate anyway is that the *output* identifies a vulnerability and points at exactly how to exploit it. A passive command that produces an attack handoff is morally active. Same gate, same rules.

---

## What netcheck will not do

There are scanning capabilities netcheck deliberately does *not* implement:

- **Exploitation.** netcheck identifies findings; it does not weaponize them. If you need a payload, use Metasploit and own that decision yourself.
- **Credential brute-forcing.** Login spraying, password lists, etc. Use Hydra or specialized tools.
- **Intercepting proxy.** netcheck doesn't sit between a browser and a server. Use Burp Suite or ZAP.
- **CVE matching at scale.** netcheck doesn't ship a vulnerability database to match versions against. Use nuclei.
- **Denial-of-service.** netcheck rate-limits its own active probes. There is no "stress test" mode and there won't be.

These tools exist for the people who need them. Lumping them into a network diagnostic muddies the legal status of the tool itself (see "Hackerparagraph" above) and turns netcheck into something it was never meant to be.

---

## Reporting findings

If you find something with netcheck — a dangling CNAME on your employer's domain, a misconfigured TLS endpoint, etc. — and you have authorization to be looking, the standard channels apply:

- Internal: file a ticket against the team that owns the asset.
- Bug bounty: submit through the program with reproduction steps. Don't include the raw netcheck JSON unless asked — most triage workflows don't want it.
- Coordinated disclosure on third-party vendors: follow the vendor's published security contact, give a reasonable deadline (90 days is the common default), keep records of every interaction.

If you don't have authorization, and you nevertheless found something serious, talk to a lawyer before talking to the target. There are paths to responsible disclosure that don't require self-incrimination, but they're case-specific.

---

## One more time

> Active scanning against systems you do not own and are not authorized to test is illegal in most places. netcheck refuses to run these commands by default because that refusal is occasionally the only thing standing between a careless user and a year-long criminal case.

`--i-have-authorization` means you have actually thought about it. Please mean it when you type it.

# netcheck report

- **Target:** `https://example.com`
- **Time:** 2026-05-21T19:30:45Z
- **Status:** OK

## DNS
| Type | IP | ASN | CDN | Reverse |
|---|---|---|---|---|
| A | `142.250.184.206` | `AS15169` GOOGLE | Google | — |
| AAAA | `2a00:1450:400d:80e::200e` | `AS15169` GOOGLE | Google | — |

_lookup time: 14ms_

## TCP
| Family | Address | Status | Time |
|---|---|---|---|
| IPv4 | `142.250.184.206:443` | OK | 21ms |
| IPv6 | `[2a00:1450:400d:80e::200e]:443` | OK | 24ms |

## TLS
- **Subject:** *.example.com
- **Issuer:** WR2
- **Protocol:** TLS 1.3 (cipher `TLS_AES_128_GCM_SHA256`)
- **Expires:** 2026-07-21 (61 days)
- **Chain:** 1 cert(s)
- **Handshake time:** 53ms

## HTTP
- **Status:** 200
- **Protocol:** HTTP/1.1
- **Server:** gws
- **Final URL:** `https://www.example.com/`
- **Redirects:** 1
  1. `301` → `https://example.com`

**Timing (ms):**
| DNS | Connect | TLS | TTFB | Total |
|---|---|---|---|---|
| 6 | 17 | 40 | 328 | 774 |


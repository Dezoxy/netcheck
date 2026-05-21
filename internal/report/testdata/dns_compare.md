# netcheck dns compare — `example.com`

_2026-05-21T19:30:45Z_

## A records

| Resolver | Address | Time | Answer |
|---|---|---|---|
| Cloudflare | `1.1.1.1:53` | 12ms | `1.1.1.1` |
| Google | `8.8.8.8:53` | 18ms | `1.1.1.1` |
| Quad9 | `9.9.9.9:53` | 14ms | `2.2.2.2` |
| Failing | `0.0.0.0:53` | 5000ms | _error: timeout_ |

**Verdict:** resolvers disagree (2 distinct answer sets).
- Set 1 (Cloudflare, Google): `1.1.1.1`
- Set 2 (Quad9): `2.2.2.2`


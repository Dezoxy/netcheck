# netcheck headers — `https://example.com/`

_2026-05-21T19:30:45Z · 145ms_

- **Status:** 200
- **Summary:** 3 pass · 2 weak · 2 missing · 1 info

| Header | Grade | Value | Note |
|---|---|---|---|
| Strict-Transport-Security | **PASS** | `max-age=31536000; includeSubDomains; preload` | Long max-age, includeSubDomains, preload directive present. |
| Content-Security-Policy | _weak_ | `default-src 'self'; script-src 'unsafe-inline'` | Present but allows 'unsafe-inline' — these weaken the XSS protection. Use nonces or hashes where possible. |
| X-Frame-Options | **PASS** | `DENY` | Set to a safe value. |
| X-Content-Type-Options | _missing_ | — | Missing — set `X-Content-Type-Options: nosniff` to prevent browsers from re-interpreting response bodies. |
| Referrer-Policy | **PASS** | `strict-origin-when-cross-origin` | Set to a value that limits cross-origin referrer leakage. |
| Permissions-Policy | _missing_ | — | Missing — controls which browser features (camera, geolocation, etc.) a page can use. Set even a permissive policy to make the surface explicit. |
| Server | _info_ | `nginx/1.25.3` | Server header exposes software identification — consider stripping or making it generic in production. |
| X-Powered-By | _weak_ | `PHP/8.1.0` | X-Powered-By leaks the application stack — remove this header. |


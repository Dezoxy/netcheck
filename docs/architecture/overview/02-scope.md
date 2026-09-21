## Scope

### In scope

- The `netcheck` binary: the CLI, the `netcheck app` local web server and the
  React workbench embedded in it.
- The published artefacts: release archives from goreleaser and the GHCR
  container image.
- Every external service the binary contacts, and the data it writes locally.

### Out of scope

- The target hosts themselves. netcheck observes them; it does not manage them.
- The external services it queries (resolvers, registries, Certificate
  Transparency logs, reverse-IP and archive APIs). Their availability, rate
  limits and terms are outside netcheck's control.
- The Homebrew tap and Scoop bucket. Both are configured in goreleaser but set
  to `skip_upload`, so neither is a live install path today.

### The trust boundary

netcheck has no server-side trust boundary of its own, because there is no
server. The boundary that matters is the user's machine: the local web server
listens on it without authentication and will run any check a caller asks for,
including active scans when the request carries the authorisation flag.

![Security view](embed:Security)

As of this edition the server checks no `Origin`, `Host` or `Content-Type`, so
any web page open in the same browser can send it requests, and the container
image binds every interface. Treat this as a known gap, not a design: it is
tracked for a fix, and this page changes when that lands.

![An authorised port scan from the workbench](embed:ActiveScanFlow)

### Known limits worth stating plainly

- `netcheck route` shells out to the operating system's `traceroute` or
  `tracert`; it does not work in the container image, which has none.
- The container image is linux/amd64 only.
- The workbench loads its fonts from Google Fonts, so opening it contacts a
  third party even when no check runs.

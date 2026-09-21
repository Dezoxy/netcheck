// Where netcheck runs. There is no hosted environment: every instance runs on
// hardware the user controls. Declared from .goreleaser.yml and the Dockerfile;
// the Homebrew and Scoop channels are configured but not publishing
// (skip_upload), so they are not modelled as install paths.
//
// External systems have no deployment instances, so the probe traffic the
// container views show is drawn here as leaving through the host's own network:
// every probe and lookup originates from the user's IP address.

workstation = deploymentEnvironment "Workstation" {
    computer = deploymentNode "User's Computer" "The laptop or workstation the user runs netcheck on." "macOS, Linux or Windows; amd64 or arm64" {
        egress = infrastructureNode "Network Egress" "The machine's own network path to the internet; probes carry the user's source IP." "Host network stack"
        process = deploymentNode "netcheck Process" "One process per CLI invocation, or a long-running netcheck app." "Static Go binary from GitHub Releases or go install" {
            cli = containerInstance netcheck.cli
            appServer = containerInstance netcheck.appServer
        }
        browser = deploymentNode "Web Browser" "Opens the workbench at http://127.0.0.1:8787." "Any current browser" {
            containerInstance netcheck.workbench
        }
        dataDir = deploymentNode "User Data Directory" "Persists across runs; not backed up by netcheck." "Local filesystem" {
            containerInstance netcheck.savedReports
        }
    }
}

workstation.computer.process.cli -> workstation.computer.egress "Sends probes, DNS queries and lookups through" "TCP, UDP, TLS, HTTP(S)" "Layer Interface"
workstation.computer.process.appServer -> workstation.computer.egress "Sends probes, DNS queries and lookups through" "TCP, UDP, TLS, HTTP(S)" "Layer Engine"

container = deploymentEnvironment "Container" {
    host = deploymentNode "Docker Host" "Any host running the published image." "Docker, linux/amd64 only" {
        egress = infrastructureNode "Network Egress" "The Docker host's network path to the internet; probes carry the host's source IP." "Docker bridge network"
        image = deploymentNode "netcheck Container" "ghcr.io/dezoxy/netcheck. Runs as UID 65532, binds 0.0.0.0:8787 and so always requires the start-up token; no traceroute binary inside." "distroless/static:nonroot" {
            appServer = containerInstance netcheck.appServer
            containerInstance netcheck.savedReports
        }
    }
    computer = deploymentNode "User's Computer" "Reaches the container through a published port." "Any OS" {
        browser = deploymentNode "Web Browser" "Opens the workbench at the published port." "Any current browser" {
            containerInstance netcheck.workbench
        }
    }
}

container.host.image.appServer -> container.host.egress "Sends probes, DNS queries and lookups through" "TCP, UDP, TLS, HTTP(S)" "Layer Engine"

// One supported way to publish netcheck on the internet: the maintainer's own
// setup, described by role. Access enforces sign-in at the edge, the Tunnel
// means no inbound port is open, and netcheck requires its token because it
// has an --allowed-host for the public name (decision 4). Declared from the
// maintainer's infrastructure code (2026-06), not from this repository.
published = deploymentEnvironment "Published" {
    device = deploymentNode "Web Browser" "On the user's device, anywhere on the internet." "Any current browser" {
        workbench = containerInstance netcheck.workbench
    }
    edge = deploymentNode "Cloudflare" "Cloudflare's edge network." "Cloudflare" {
        access = softwareSystemInstance cfAccess
        tunnel = infrastructureNode "Cloudflare Tunnel" "Carries requests from the edge into the private network; no inbound port is open there." "cloudflared"
    }
    private = deploymentNode "Private Network" "A homelab network behind the tunnel." "Proxmox" {
        proxyHost = deploymentNode "Reverse-Proxy Host" "Terminates the tunnel's traffic for every published app." "LXC container" {
            proxy = infrastructureNode "Reverse Proxy" "Routes the public netcheck name to the app host, keeping the Host header." "Traefik"
        }
        appHost = deploymentNode "App Host" "Runs published apps with Docker Compose." "VM" {
            ctr = deploymentNode "netcheck Container" "Pinned image version, started with --allowed-host for the public name, so the token is required." "ghcr.io/dezoxy/netcheck" {
                appServer = containerInstance netcheck.appServer
                containerInstance netcheck.savedReports
            }
        }
    }
}

published.edge.access -> published.edge.tunnel "Forwards signed-in requests through" "HTTPS"
published.edge.tunnel -> published.private.proxyHost.proxy "Delivers requests to" "HTTP, private network"
published.private.proxyHost.proxy -> published.private.appHost.ctr.appServer "Forwards requests to" "HTTP :8787"

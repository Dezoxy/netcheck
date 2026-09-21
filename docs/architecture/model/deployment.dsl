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
        image = deploymentNode "netcheck Container" "ghcr.io/dezoxy/netcheck. Runs as UID 65532 and binds 0.0.0.0:8787; no traceroute binary inside." "distroless/static:nonroot" {
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

// Each view answers one question. Keep structural views under ~10 elements /
// 12 arrows and split a view before trying to style it into readability.

systemContext netcheck "SystemContext" "What does netcheck talk to, and who uses it?" {
    include *
    // The (refused) cross-site path is a security concern, not context; it
    // lives in the Security view.
    exclude otherSites
    autoLayout lr
}

// Building blocks only. The CLI and server's probe targets are the
// ProbeDependencies view's question; drawn here they doubled the arrows.
container netcheck "Containers" "What are netcheck's building blocks, and how does the workbench reach the probe engine?" {
    include user netcheck.workbench netcheck.cli netcheck.appServer netcheck.savedReports googleFonts
    // Default rank spacing put the "Browser" group label on top of the
    // workbench -> server arrow label; 350 separates them.
    autoLayout tb 350 300
}

container netcheck "ProbeDependencies" "Which external services do the CLI and the local web server query or probe?" {
    include netcheck.cli netcheck.appServer targets resolvers registries reconServices
    autoLayout tb 400 300
}

container netcheck "Security" "Who can reach the local web server, where is sign-in enforced, and what can it do on their behalf?" {
    include user netcheck.workbench netcheck.appServer netcheck.savedReports otherSites targets cfAccess
    autoLayout tb
}

dynamic netcheck "ActiveScanFlow" "What happens when the user runs an authorised port scan from the workbench and saves the result?" {
    user -> netcheck.workbench "Acknowledges authorisation and starts a port scan"
    netcheck.workbench -> netcheck.appServer "POSTs the scan with i_have_authorization set and reads progress over SSE"
    netcheck.appServer -> targets "Connects to each requested port"
    netcheck.workbench -> netcheck.appServer "Saves the finished report"
    netcheck.appServer -> netcheck.savedReports "Writes the report as a 0600 JSON file"
    autoLayout lr
}

deployment netcheck "Workstation" "WorkstationDeployment" "Where does netcheck run when installed on the user's own machine?" {
    include *
    autoLayout lr
}

deployment netcheck "Container" "ContainerDeployment" "Where does netcheck run when started from the GHCR image?" {
    include *
    autoLayout lr
}

// The published instance. The implied browser -> server and Access -> server
// arrows are excluded: here every request goes through Access, the Tunnel
// and the reverse proxy, and a direct arrow would hide exactly that.
deployment netcheck "Published" "PublishedDeployment" "How is a published instance reached from the internet, and where is sign-in enforced?" {
    include *
    exclude "published.device.workbench -> published.private.appHost.ctr.appServer"
    exclude "published.edge.access -> published.private.appHost.ctr.appServer"
    autoLayout lr
}

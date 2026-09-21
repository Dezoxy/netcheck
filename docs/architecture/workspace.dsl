// Entry point for the Netcheck architecture model. Keep this file at
// docs/architecture/: !docs and !adrs paths must be this directory or below.
// Model fragments live in model/ and are pulled in with !include (order matters).
workspace "Netcheck" "Architecture model for netcheck: a single-binary network diagnostics CLI with a local web workbench. It runs on the user's own machine; there is no hosted service." {

    !identifiers hierarchical

    configuration {
        scope softwaresystem
    }

    // Attached to the workspace, not the software system, so the path resolves
    // unambiguously against this file.
    !docs overview
    !adrs decisions

    properties {
        // Docs are attached at workspace level (above), so the per-system
        // documentation/decision inspections do not apply here.
        "structurizr.inspection.model.softwaresystem.documentation" "ignore"
        "structurizr.inspection.model.softwaresystem.decisions" "ignore"
    }

    model {
        !include model/people-systems.dsl
        !include model/containers.dsl
        !include model/deployment.dsl
    }

    views {
        !include model/views.dsl
        !include model/styles.dsl
    }

}

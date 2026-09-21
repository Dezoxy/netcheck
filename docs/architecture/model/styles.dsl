// This repository's styles. The shared meanings (people, systems, external,
// shapes, security markings, arrows) and the approved palette come from
// styles-shared.dsl, copied unchanged from architecture-base. This file only maps
// netcheck's layers and groups onto palette families.
// Tag order matters on an element: layer tag first, security marking last.

styles {
    !include styles-shared.dsl

    // Layers: Interface purple (what the user touches), Engine green (the
    // server that runs probes), Data slate (what persists).
    element "Layer Interface" {
        background ${PURPLE_FILL}
        stroke ${PURPLE_STROKE}
    }
    relationship "Layer Interface" {
        color ${PURPLE_STROKE}
    }
    element "Layer Engine" {
        background ${GREEN_FILL}
        stroke ${GREEN_STROKE}
    }
    relationship "Layer Engine" {
        color ${GREEN_STROKE}
    }
    element "Layer Data" {
        background ${SLATE_FILL}
        stroke ${SLATE_STROKE}
    }
    relationship "Layer Data" {
        color ${SLATE_STROKE}
    }

    // Groups mark where each part runs.
    element "Group:Browser" {
        color ${PURPLE_LABEL}
        stroke ${PURPLE_STROKE}
        background ${PURPLE_FRAME}
    }
    element "Group:User's machine" {
        color ${SLATE_LABEL}
        stroke ${SLATE_STROKE}
        background ${SLATE_FRAME}
    }
}

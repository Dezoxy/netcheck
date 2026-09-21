## Quality attributes

Quality scenarios with the evidence that exists today. A target is not a
measurement: the "Current evidence" column says what has actually been checked.

| ID | Quality | Scenario | Expected response | Validation | Current evidence | Gap |
|---|---|---|---|---|---|---|
| QA-01 | Compatibility | An integrator upgrades from one v2.x release to a later one. | Their scripts and Go code keep working: no field, flag or exit code they rely on is removed or renamed. | The STABILITY.md contract (C-03); `SchemaVersion` and the `kind` discriminator in `pkg/report/jsonschema.go`. | CHANGELOG has no breaking-change entry after v2.0.0 (2026-05-25). | No automated check compares the schema between releases; compliance rests on review. |
| QA-02 | Portability | A release is cut. | Working binaries for macOS, Linux and Windows on amd64 and arm64, plus a linux/amd64 container image. | The CI cross-compile matrix and its `version` smoke test (`.github/workflows/ci.yml`); goreleaser builds. | All six targets build on every pull request. | The container image is amd64 only (TD-004); `route` does not work inside it (TD-002). |
| QA-03 | Privacy | The user runs any check. | Nothing is reported to the maintainers; only the check's own traffic leaves the machine. | `pkg/telemetry` and `pkg/eventbus` import no network packages; config and reports stay local. | No telemetry endpoint exists in the code. | The workbench fetches fonts from Google on every load, before any check runs (TD-003). |
| QA-04 | Safety of active checks | Someone starts an active check without authorisation. | The CLI exits 2 with an explanation; the API answers 403. | `cmd/authz_test.go`, `cmd/app_v14_endpoints_test.go`. | Both tests pass in CI. | Browsers are refused cross-origin (RISK-001, resolved), but a non-browser client that reaches the port can still send the flag (RISK-003). |

## ADDED Requirements

### Requirement: AMPEL provider declares export support
The AMPEL provider's `Describe` RPC response SHALL set `SupportsExport: true` so that complyctl includes it in the export phase when `--format otel` is used.

#### Scenario: Describe reports export capability
- **WHEN** complyctl calls `Describe` on the AMPEL provider
- **THEN** the response includes `SupportsExport: true` alongside the existing health, version, and required variable fields

### Requirement: AMPEL provider implements Export RPC
The AMPEL provider `ProviderServer` SHALL implement the `provider.Exporter` interface by providing an `Export(ctx, *ExportRequest) (*ExportResponse, error)` method. The method SHALL read AMPEL scan results from the workspace results directory, convert each assessment to a `GemaraEvidence` object, and emit them as OTLP log records via ProofWatch to the collector endpoint specified in the `ExportRequest.Collector` config.

#### Scenario: Successful export of AMPEL scan results
- **WHEN** complyctl calls `Export` with a valid `CollectorConfig` (endpoint and auth token) after a successful scan that produced results in `.complytime/ampel/results/`
- **THEN** the AMPEL provider reads per-repo result files, converts each assessment finding to a `GemaraEvidence` with the correct Gemara attribute mappings, emits them via ProofWatch, and returns an `ExportResponse` with `Success: true` and `ExportedCount` equal to the number of evidence records emitted

#### Scenario: Export with no scan results
- **WHEN** complyctl calls `Export` but no scan result files exist in the results directory
- **THEN** the provider returns `ExportResponse` with `Success: true`, `ExportedCount: 0`, and `FailedCount: 0`

#### Scenario: Export with collector connection failure
- **WHEN** complyctl calls `Export` with a `CollectorConfig` pointing to an unreachable endpoint
- **THEN** the provider returns `ExportResponse` with `Success: false` and `ErrorMessage` describing the connection failure

### Requirement: AMPEL evidence carries correct Gemara attributes
Each `GemaraEvidence` record emitted by the AMPEL provider SHALL carry the following OTEL attributes mapped from the scan results:

- `policy.engine.name` SHALL be set to `"ampel"`
- `compliance.control.id` SHALL be set to the requirement ID from the assessment finding
- `policy.rule.id` SHALL be set to the policy ID that produced the finding
- `policy.evaluation.result` SHALL map `ResultPassed` to `gemara.Passed` and `ResultFailed` to `gemara.Failed`
- `compliance.assessment.id` SHALL be a unique identifier per evidence record
- `policy.evaluation.message` SHALL include the step message from the finding when present

#### Scenario: Passed finding maps to correct attributes
- **WHEN** an AMPEL scan produces a finding with `Result: ResultPassed` for requirement `"branch-protection-01"` from policy `"require-branch-protection"`
- **THEN** the emitted `GemaraEvidence` has `policy.engine.name = "ampel"`, `compliance.control.id = "branch-protection-01"`, `policy.rule.id = "require-branch-protection"`, and `policy.evaluation.result = "Passed"`

#### Scenario: Failed finding maps to correct attributes
- **WHEN** an AMPEL scan produces a finding with `Result: ResultFailed` for requirement `"approval-rules-01"`
- **THEN** the emitted `GemaraEvidence` has `policy.evaluation.result = "Failed"` and includes the step message in `policy.evaluation.message`

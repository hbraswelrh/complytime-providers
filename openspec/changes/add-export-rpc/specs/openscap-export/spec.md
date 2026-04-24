## ADDED Requirements

### Requirement: OpenSCAP provider declares export support
The OpenSCAP provider's `Describe` RPC response SHALL set `SupportsExport: true` so that complyctl includes it in the export phase when `--format otel` is used.

#### Scenario: Describe reports export capability
- **WHEN** complyctl calls `Describe` on the OpenSCAP provider
- **THEN** the response includes `SupportsExport: true` alongside the existing health, version, and required variable fields

### Requirement: OpenSCAP provider implements Export RPC
The OpenSCAP provider `ProviderServer` SHALL implement the `provider.Exporter` interface by providing an `Export(ctx, *ExportRequest) (*ExportResponse, error)` method. The method SHALL read OpenSCAP scan results from the workspace ARF XML file, convert each assessment to a `GemaraEvidence` object, and emit them as OTLP log records via ProofWatch to the collector endpoint specified in the `ExportRequest.Collector` config.

#### Scenario: Successful export of OpenSCAP scan results
- **WHEN** complyctl calls `Export` with a valid `CollectorConfig` (endpoint and auth token) after a successful scan that produced an ARF file at `.complytime/openscap/results/arf.xml`
- **THEN** the OpenSCAP provider reads and parses the ARF file, converts each rule-result assessment to a `GemaraEvidence` with the correct Gemara attribute mappings, emits them via ProofWatch, and returns an `ExportResponse` with `Success: true` and `ExportedCount` equal to the number of evidence records emitted

#### Scenario: Export with no ARF file
- **WHEN** complyctl calls `Export` but no ARF file exists at the expected path
- **THEN** the provider returns `ExportResponse` with `Success: false` and `ErrorMessage` indicating no scan results are available for export

#### Scenario: Export with collector connection failure
- **WHEN** complyctl calls `Export` with a `CollectorConfig` pointing to an unreachable endpoint
- **THEN** the provider returns `ExportResponse` with `Success: false` and `ErrorMessage` describing the connection failure

### Requirement: OpenSCAP evidence carries correct Gemara attributes
Each `GemaraEvidence` record emitted by the OpenSCAP provider SHALL carry the following OTEL attributes mapped from the scan results:

- `policy.engine.name` SHALL be set to `"openscap"`
- `compliance.control.id` SHALL be set to the requirement ID extracted from the OVAL check-content-ref name
- `policy.rule.id` SHALL be set to the XCCDF rule ID ref
- `policy.evaluation.result` SHALL map `pass`/`fixed` to `gemara.Passed`, `fail` to `gemara.Failed`, and `error`/`unknown` to `gemara.Unknown`
- `compliance.assessment.id` SHALL be a unique identifier per evidence record
- `policy.evaluation.message` SHALL include the rule title and any diagnostic messages from the rule-result

#### Scenario: Passed rule-result maps to correct attributes
- **WHEN** an OpenSCAP scan produces a rule-result with status `pass` for XCCDF rule `xccdf_org.ssgproject.content_rule_audit_rules_login_events` with OVAL-derived requirement ID `audit_rules_login_events`
- **THEN** the emitted `GemaraEvidence` has `policy.engine.name = "openscap"`, `compliance.control.id = "audit_rules_login_events"`, `policy.rule.id = "xccdf_org.ssgproject.content_rule_audit_rules_login_events"`, and `policy.evaluation.result = "Passed"`

#### Scenario: Failed rule-result maps to correct attributes
- **WHEN** an OpenSCAP scan produces a rule-result with status `fail` for a rule with title "Ensure audit rules for login events"
- **THEN** the emitted `GemaraEvidence` has `policy.evaluation.result = "Failed"` and `policy.evaluation.message` includes the rule title

#### Scenario: Skippable results are excluded from export
- **WHEN** an OpenSCAP scan produces rule-results with status `notselected` or `notapplicable`
- **THEN** no `GemaraEvidence` records are emitted for those results, consistent with the existing scan behavior

## Context

The complyctl plugin SDK (vendored at `vendor/github.com/complytime/complyctl/pkg/provider/`) already defines the full Export RPC contract:

- `Exporter` interface with `Export(ctx, *ExportRequest) (*ExportResponse, error)`
- `ExportRequest` carrying `CollectorConfig` (endpoint + auth token)
- `ExportResponse` with success/count/error fields
- `grpcServer.Export()` does a runtime type assertion to check if a provider implements `Exporter`
- `DescribeResponse.SupportsExport` boolean for capability discovery
- `Manager.RouteExport()` for dispatching to capable plugins

Neither the AMPEL nor OpenSCAP provider implements the `Exporter` interface today. Both providers produce scan results (assessment logs) that need to be converted to `GemaraEvidence` objects and emitted via the ProofWatch library as OTLP log records to a Beacon collector.

ProofWatch (`github.com/complytime/complybeacon/proofwatch`) provides the `GemaraEvidence` type wrapping `gemara.Metadata` + `gemara.AssessmentLog`, and the `ProofWatch.Log(ctx, evidence)` method that emits OTEL log records through a configurable `LoggerProvider`.

## Goals / Non-Goals

**Goals:**

- Both providers satisfy the `provider.Exporter` interface
- Both providers declare `SupportsExport: true` in `Describe`
- Scan results are converted to `GemaraEvidence` using the correct Gemara attribute mappings
- OTEL log records are emitted directly from the plugin process to the collector via OTLP gRPC
- Export logic is unit-testable with a noop LoggerProvider
- Existing scan/generate behavior is completely unaffected

**Non-Goals:**

- No changes to the vendored complyctl SDK or proto definitions
- No custom OTLP transport or retry logic (the OTEL SDK handles this)
- No enrichment logic (TruthBeam in the collector handles enrichment)
- No OTLP HTTP fallback (gRPC only for initial implementation)
- No end-to-end integration tests against a real collector (unit tests with noop providers only)

## Decisions

### D1: Shared `export` package per provider vs. a common shared package

Each provider gets its own `export/` package (`cmd/ampel-provider/export/` and `cmd/openscap-provider/export/`). The conversion logic is provider-specific — AMPEL reads JSON attestation results from disk while OpenSCAP reads ARF XML results. The only shared concern is ProofWatch initialization, which is a few lines of code not worth abstracting.

**Alternative considered**: A single `internal/export/` shared package. Rejected because the result-to-evidence conversion is different for each provider, and a shared package would need provider-specific interfaces adding unnecessary indirection.

### D2: OTEL SDK setup lives in the export package

Each provider's `export` package creates the OTLP gRPC log exporter, `sdklog.LoggerProvider`, and `ProofWatch` instance from the `CollectorConfig` received in the `ExportRequest`. The setup and teardown happen within the scope of a single `Export` RPC call. The `LoggerProvider` is shut down (flushing buffered logs) before the RPC returns.

**Alternative considered**: Initializing the OTEL stack once at provider startup and reusing across calls. Rejected because Export is called at most once per scan invocation, and per-call setup avoids state management complexity. The collector config (endpoint, token) comes from the `ExportRequest`, which is only available at call time.

### D3: Scan results are read from workspace disk, not in-memory state

Both providers write scan results to the workspace directory during `Scan` (AMPEL writes per-repo JSON, OpenSCAP writes ARF XML). The `Export` method reads these same files to build `GemaraEvidence` objects. This avoids adding mutable state to the `ProviderServer` struct and aligns with the existing stateless-server pattern.

**Alternative considered**: Storing scan results in memory on the `ProviderServer` between Scan and Export calls. Rejected because it introduces mutable state, complicates testing, and the files are already written as part of the scan flow.

### D4: Bearer token auth via OTLP exporter headers

The `CollectorConfig.AuthToken` (a resolved bearer token from complyctl's OIDC exchange) is passed as an `Authorization: Bearer <token>` header via `otlploggrpc.WithHeaders()`. This is the standard OTLP gRPC auth mechanism.

### D5: Result-to-Gemara mapping

Provider scan results map to Gemara types as follows:

| Provider Domain | Gemara Field | OTEL Attribute |
|---|---|---|
| Provider name ("ampel" / "openscap") | `Metadata.Author.Name` | `policy.engine.name` |
| `AssessmentLog.RequirementID` | `AssessmentLog.Requirement.EntryId` | `compliance.control.id` |
| Assessment plan ID | `AssessmentLog.Plan.EntryId` | `policy.rule.id` |
| `ResultPassed`/`ResultFailed`/etc. | `AssessmentLog.Result` (gemara.Passed/Failed/etc.) | `policy.evaluation.result` |
| Step messages | `AssessmentLog.Message` | `policy.evaluation.message` |
| Generated UUID | `Metadata.Id` | `compliance.assessment.id` |

## Risks / Trade-offs

- **[Risk] OTEL SDK version compatibility**: ProofWatch depends on `go.opentelemetry.io/otel/log v0.16.0`. The `sdk/log` and `otlploggrpc` exporter packages must use compatible versions. → **Mitigation**: Pin to `v0.16.0` for the log-related experimental packages and run `go mod tidy` to verify compatibility.

- **[Risk] Per-call OTEL setup overhead**: Creating and shutting down the OTLP exporter and LoggerProvider for each Export call adds latency (connection setup, TLS handshake, flush timeout). → **Mitigation**: Acceptable for the expected use case (one Export call per scan run). The batch processor flush timeout is bounded at 10 seconds.

- **[Trade-off] Disk-based result reading**: Reading results from disk couples Export to the file layout written by Scan. If the file layout changes, Export must change too. → **Mitigation**: Both are in the same provider binary and tested together. The coupling is intentional and local.

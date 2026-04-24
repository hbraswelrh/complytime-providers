## Why

Both the AMPEL and OpenSCAP provider plugins currently lack Export RPC support. The complyctl SDK already defines the `Exporter` interface and the gRPC plumbing (`Export` RPC, `ExportRequest`/`ExportResponse`, `CollectorConfig`), but neither plugin implements it. When `complyctl scan --format otel` is used, these plugins are skipped. Implementing Export in both plugins enables direct evidence shipping to a Beacon collector via ProofWatch, completing the end-to-end compliance evidence pipeline without manual transfer.

## What Changes

- Add `Export` method to the AMPEL provider (`cmd/ampel-provider/server/server.go`) that satisfies the `provider.Exporter` interface
- Add `Export` method to the OpenSCAP provider (`cmd/openscap-provider/server/server.go`) that satisfies the `provider.Exporter` interface
- Set `SupportsExport: true` in both providers' `Describe` responses
- Add ProofWatch dependency (`github.com/complytime/complybeacon/proofwatch`) to `go.mod`
- Add an `export` package to each provider for converting scan results to `GemaraEvidence` and emitting via ProofWatch
- Add unit tests for the export logic in both providers

## Capabilities

### New Capabilities

- `ampel-export`: AMPEL provider implements the Export RPC, converting AMPEL scan results to GemaraEvidence and emitting them as OTLP log records via ProofWatch
- `openscap-export`: OpenSCAP provider implements the Export RPC, converting OpenSCAP scan results to GemaraEvidence and emitting them as OTLP log records via ProofWatch

### Modified Capabilities


## Impact

- **Code**: `cmd/ampel-provider/server/server.go`, `cmd/openscap-provider/server/server.go` gain Export methods; new `export/` packages in each provider
- **Dependencies**: `github.com/complytime/complybeacon/proofwatch` and transitive OTEL SDK dependencies added to `go.mod`
- **APIs**: No proto changes needed; the Export RPC is already defined in the vendored complyctl SDK. Both providers now declare `supports_export: true`
- **Testing**: New unit tests for export conversion and ProofWatch integration; existing tests remain unchanged

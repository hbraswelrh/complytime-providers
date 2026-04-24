## 1. Dependencies

- [ ] 1.1 Add `github.com/complytime/complybeacon/proofwatch` and `github.com/gemaraproj/go-gemara` to `go.mod` with compatible versions
- [ ] 1.2 Add OTEL SDK log dependencies: `go.opentelemetry.io/otel/sdk/log` and `go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc`
- [ ] 1.3 Run `go mod tidy` and `go mod vendor` to resolve and vendor all transitive dependencies

## 2. AMPEL Provider Export

- [ ] 2.1 Create `cmd/ampel-provider/export/export.go` with OTEL SDK setup function: create OTLP gRPC log exporter from `CollectorConfig`, build `sdklog.LoggerProvider` with batch processor, initialize ProofWatch, return shutdown function
- [ ] 2.2 Create `cmd/ampel-provider/export/convert.go` with function to read AMPEL per-repo result JSON files from the results directory and convert each finding to a `GemaraEvidence` object with correct attribute mappings (engine=ampel, requirement ID, policy ID, result mapping, UUID for assessment ID)
- [ ] 2.3 Add `Export` method to `cmd/ampel-provider/server/server.go` `ProviderServer` that calls the export package to set up ProofWatch, convert results, emit evidence, and return `ExportResponse` with counts
- [ ] 2.4 Update `Describe` in `cmd/ampel-provider/server/server.go` to set `SupportsExport: true`
- [ ] 2.5 Add compile-time interface assertion `var _ provider.Exporter = (*ProviderServer)(nil)` to `cmd/ampel-provider/server/server.go`

## 3. OpenSCAP Provider Export

- [ ] 3.1 Create `cmd/openscap-provider/export/export.go` with OTEL SDK setup function (same pattern as AMPEL: OTLP gRPC exporter, LoggerProvider, ProofWatch init, shutdown)
- [ ] 3.2 Create `cmd/openscap-provider/export/convert.go` with function to read the ARF XML file, parse rule-results (reusing existing `buildAssessmentsFromARF` logic or the ARF file directly), and convert each assessment to a `GemaraEvidence` object with correct attribute mappings (engine=openscap, OVAL-derived requirement ID, XCCDF rule ID, result mapping, UUID)
- [ ] 3.3 Add `Export` method to `cmd/openscap-provider/server/server.go` `ProviderServer` that calls the export package to set up ProofWatch, convert results, emit evidence, and return `ExportResponse` with counts
- [ ] 3.4 Update `Describe` in `cmd/openscap-provider/server/server.go` to set `SupportsExport: true`
- [ ] 3.5 Add compile-time interface assertion `var _ provider.Exporter = (*ProviderServer)(nil)` to `cmd/openscap-provider/server/server.go`

## 4. Tests

- [ ] 4.1 Create `cmd/ampel-provider/export/convert_test.go` with tests for result-to-GemaraEvidence conversion: passed findings, failed findings, empty results, correct attribute values
- [ ] 4.2 Create `cmd/ampel-provider/export/export_test.go` with tests for OTEL setup function using noop LoggerProvider
- [ ] 4.3 Update `cmd/ampel-provider/server/server_test.go` with tests for Export method: successful export, no results, and Describe now returning SupportsExport=true
- [ ] 4.4 Create `cmd/openscap-provider/export/convert_test.go` with tests for ARF-to-GemaraEvidence conversion: passed rules, failed rules, skippable results excluded, correct attribute values
- [ ] 4.5 Create `cmd/openscap-provider/export/export_test.go` with tests for OTEL setup function using noop LoggerProvider
- [ ] 4.6 Update `cmd/openscap-provider/server/server_test.go` with tests for Export method: successful export, missing ARF file, and Describe now returning SupportsExport=true

## 5. Verification

- [ ] 5.1 Run `go build ./...` to verify both providers compile with the new Export implementation
- [ ] 5.2 Run `go test -race -v ./...` to verify all existing and new tests pass
- [ ] 5.3 Run `go vet ./...` to verify no vet issues

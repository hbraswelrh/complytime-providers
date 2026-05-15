# complytime-providers

Provider plugins for [complyctl](https://github.com/complytime/complyctl).

## Providers

| Provider | Binary | Description |
|:---|:---|:---|
| `cmd/openscap-provider` | `complyctl-provider-openscap` | OpenSCAP-based compliance scanning |
| `cmd/ampel-provider` | `complyctl-provider-ampel` | AMPEL-based policy evaluation |
| `cmd/opa-provider` | `complyctl-provider-opa` | OPA/conftest-based policy evaluation |

The openscap and ampel providers support evidence export via OTLP (`complyctl scan --format otel`),
shipping compliance evidence as structured log records to a Beacon collector
via [ProofWatch](https://github.com/complytime/complybeacon).

## Building

```bash
make build
```

## Documentation

See [docs/provider-guide.md](docs/provider-guide.md) for the provider
development guide, including the Export interface.


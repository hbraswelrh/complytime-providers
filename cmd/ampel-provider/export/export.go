// SPDX-License-Identifier: Apache-2.0

package export

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/complytime/complybeacon/proofwatch"
	"github.com/complytime/complyctl/pkg/provider"
)

const shutdownTimeout = 10 * time.Second

// Emitter wraps a ProofWatch instance and its cleanup function.
type Emitter struct {
	PW             *proofwatch.ProofWatch
	loggerProvider *sdklog.LoggerProvider
}

// NewEmitter creates an OTLP gRPC log exporter, LoggerProvider, and ProofWatch
// instance configured to emit evidence to the given collector endpoint.
func NewEmitter(ctx context.Context, cfg provider.CollectorConfig) (*Emitter, error) {
	opts := []otlploggrpc.Option{
		otlploggrpc.WithEndpoint(cfg.Endpoint),
	}
	if cfg.AuthToken != "" {
		opts = append(opts, otlploggrpc.WithHeaders(map[string]string{
			"Authorization": "Bearer " + cfg.AuthToken,
		}))
	}

	exporter, err := otlploggrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating OTLP log exporter: %w", err)
	}

	loggerProvider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(
			sdklog.NewBatchProcessor(exporter),
		),
	)

	pw, err := proofwatch.NewProofWatch(
		proofwatch.WithLoggerProvider(loggerProvider),
	)
	if err != nil {
		_ = loggerProvider.Shutdown(ctx)
		return nil, fmt.Errorf("creating ProofWatch: %w", err)
	}

	return &Emitter{
		PW:             pw,
		loggerProvider: loggerProvider,
	}, nil
}

// Shutdown flushes buffered logs and releases resources.
func (e *Emitter) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	return e.loggerProvider.Shutdown(ctx)
}

// SPDX-License-Identifier: Apache-2.0

package export

import (
	"context"
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/complytime/complybeacon/proofwatch"
	"github.com/complytime/complyctl/pkg/provider"
)

func TestNewEmitter_Success(t *testing.T) {
	// NewEmitter creates an OTLP gRPC exporter. The gRPC connection is
	// lazy/async, so this succeeds even without a running collector.
	ctx := context.Background()
	cfg := provider.CollectorConfig{
		Endpoint: "localhost:4317",
	}

	emitter, err := NewEmitter(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, emitter)
	require.NotNil(t, emitter.PW)

	// Shutdown cleans up resources. It will timeout trying to flush
	// to the non-existent collector but should not return a fatal error.
	_ = emitter.Shutdown()
}

func TestNewEmitter_WithAuthToken(t *testing.T) {
	ctx := context.Background()
	cfg := provider.CollectorConfig{
		Endpoint:  "localhost:4317",
		AuthToken: "test-bearer-token",
	}

	emitter, err := NewEmitter(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, emitter)
	require.NotNil(t, emitter.PW)

	_ = emitter.Shutdown()
}

func TestNewEmitter_EmptyAuthToken(t *testing.T) {
	// When AuthToken is empty, no Authorization header is added.
	ctx := context.Background()
	cfg := provider.CollectorConfig{
		Endpoint:  "localhost:4317",
		AuthToken: "",
	}

	emitter, err := NewEmitter(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, emitter)

	_ = emitter.Shutdown()
}

func TestEmitter_LogWithNewEmitter(t *testing.T) {
	ctx := context.Background()
	cfg := provider.CollectorConfig{
		Endpoint: "localhost:4317",
	}

	emitter, err := NewEmitter(ctx, cfg)
	require.NoError(t, err)

	ev := proofwatch.GemaraEvidence{
		Metadata: gemara.Metadata{
			Id: "test-evidence-1",
			Author: gemara.Actor{
				Name: "ampel",
				Type: gemara.Software,
			},
		},
		AssessmentLog: gemara.AssessmentLog{
			Requirement: gemara.EntryMapping{EntryId: "BP-1.01"},
			Result:      gemara.Passed,
			Message:     "test evidence",
		},
	}

	// Log succeeds — the batch processor buffers the record.
	err = emitter.PW.Log(ctx, ev)
	assert.NoError(t, err)

	_ = emitter.Shutdown()
}

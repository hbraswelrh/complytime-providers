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

func TestNewEmitter_EmptyEndpoint(t *testing.T) {
	ctx := context.Background()
	cfg := provider.CollectorConfig{
		Endpoint: "",
	}

	emitter, err := NewEmitter(ctx, cfg)
	require.Error(t, err)
	assert.Nil(t, emitter)
	assert.Contains(t, err.Error(), "collector endpoint must not be empty")
}

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
				Name: "openscap",
				Type: gemara.Software,
			},
		},
		AssessmentLog: gemara.AssessmentLog{
			Requirement: gemara.EntryMapping{EntryId: "audit_perm_change_success"},
			Result:      gemara.Passed,
			Message:     "test evidence",
		},
	}

	err = emitter.PW.Log(ctx, ev)
	assert.NoError(t, err)

	_ = emitter.Shutdown()
}

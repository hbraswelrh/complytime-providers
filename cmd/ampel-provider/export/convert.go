// SPDX-License-Identifier: Apache-2.0

package export

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gemaraproj/go-gemara"

	"github.com/complytime/complybeacon/proofwatch"
)

const engineName = "ampel"

// perRepoResult mirrors the results.PerRepoResult type for JSON unmarshalling.
// We re-declare it here to avoid a circular import with the results package.
type perRepoResult struct {
	Repository string    `json:"repository"`
	Branch     string    `json:"branch"`
	ScannedAt  time.Time `json:"scanned_at"`
	Findings   []finding `json:"findings"`
	Status     string    `json:"status"`
	Error      string    `json:"error,omitempty"`
}

// finding mirrors results.Finding.
type finding struct {
	TenetID string `json:"tenet_id"`
	Title   string `json:"title"`
	Result  string `json:"result"`
	Reason  string `json:"reason"`
}

// ReadAndConvert reads per-repo result JSON files from the results directory
// and converts each finding to a GemaraEvidence object.
func ReadAndConvert(resultsDir string) ([]proofwatch.GemaraEvidence, error) {
	entries, err := os.ReadDir(resultsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading results directory: %w", err)
	}

	var evidence []proofwatch.GemaraEvidence
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		data, err := os.ReadFile(filepath.Join(resultsDir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("reading result file %s: %w", entry.Name(), err)
		}

		var result perRepoResult
		if err := json.Unmarshal(data, &result); err != nil {
			return nil, fmt.Errorf("parsing result file %s: %w", entry.Name(), err)
		}

		converted := convertResult(&result)
		evidence = append(evidence, converted...)
	}

	return evidence, nil
}

// convertResult converts a single per-repo result into GemaraEvidence records.
func convertResult(result *perRepoResult) []proofwatch.GemaraEvidence {
	var evidence []proofwatch.GemaraEvidence

	for _, f := range result.Findings {
		reqID := strings.TrimPrefix(f.TenetID, "check-")
		assessmentID := fmt.Sprintf("%s-%s-%s-%s", engineName, reqID, result.Repository, result.Branch)

		ev := proofwatch.GemaraEvidence{
			Metadata: gemara.Metadata{
				Id: assessmentID,
				Author: gemara.Actor{
					Name: engineName,
					Type: gemara.Software,
				},
			},
			AssessmentLog: gemara.AssessmentLog{
				Requirement: gemara.EntryMapping{
					EntryId: reqID,
				},
				Plan: &gemara.EntryMapping{
					EntryId: reqID,
				},
				Result:  mapResult(f.Result),
				Message: f.Reason,
				End:     gemara.Datetime(result.ScannedAt.Format(time.RFC3339)),
			},
		}

		evidence = append(evidence, ev)
	}

	return evidence
}

// mapResult maps an AMPEL finding result string to a gemara.Result.
func mapResult(result string) gemara.Result {
	switch result {
	case "pass":
		return gemara.Passed
	case "fail":
		return gemara.Failed
	default:
		return gemara.Unknown
	}
}



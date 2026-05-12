// SPDX-License-Identifier: Apache-2.0

package export

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gemaraproj/go-gemara"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeResultFile(t *testing.T, dir string, result *perRepoResult) {
	t.Helper()
	data, err := json.MarshalIndent(result, "", "  ")
	require.NoError(t, err)
	filename := filepath.Join(dir, result.Repository+"-"+result.Branch+".json")
	require.NoError(t, os.WriteFile(filename, data, 0600))
}

func TestReadAndConvert_PassedFindings(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)

	writeResultFile(t, dir, &perRepoResult{
		Repository: "myorg-repo1",
		Branch:     "main",
		ScannedAt:  ts,
		Findings: []finding{
			{TenetID: "check-BP-1.01", Title: "Branch protection enabled", Result: "pass", Reason: "all checks pass"},
		},
		Status: "complete",
	})

	evidence, err := ReadAndConvert(dir)
	require.NoError(t, err)
	require.Len(t, evidence, 1)

	ev := evidence[0]
	assert.Equal(t, "ampel", ev.Metadata.Author.Name)
	assert.Equal(t, gemara.Software, ev.Metadata.Author.Type)
	assert.Equal(t, "BP-1.01", ev.Requirement.EntryId)
	assert.Equal(t, "BP-1.01", ev.Plan.EntryId)
	assert.Equal(t, gemara.Passed, ev.Result)
	assert.Equal(t, "all checks pass", ev.Message)
	assert.Equal(t, "ampel-BP-1.01-myorg-repo1-main", ev.Metadata.Id)
}

func TestReadAndConvert_FailedFindings(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)

	writeResultFile(t, dir, &perRepoResult{
		Repository: "myorg-repo1",
		Branch:     "main",
		ScannedAt:  ts,
		Findings: []finding{
			{TenetID: "check-BP-2.01", Title: "Signed commits required", Result: "fail", Reason: "unsigned commits found"},
		},
		Status: "complete",
	})

	evidence, err := ReadAndConvert(dir)
	require.NoError(t, err)
	require.Len(t, evidence, 1)

	ev := evidence[0]
	assert.Equal(t, gemara.Failed, ev.Result)
	assert.Equal(t, "unsigned commits found", ev.Message)
	assert.Equal(t, "BP-2.01", ev.Requirement.EntryId)
}

func TestReadAndConvert_EmptyResults(t *testing.T) {
	dir := t.TempDir()

	// No files in directory
	evidence, err := ReadAndConvert(dir)
	require.NoError(t, err)
	assert.Empty(t, evidence)
}

func TestReadAndConvert_NonexistentDir(t *testing.T) {
	evidence, err := ReadAndConvert("/nonexistent/path")
	require.NoError(t, err)
	assert.Nil(t, evidence)
}

func TestReadAndConvert_MultipleFindings(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)

	writeResultFile(t, dir, &perRepoResult{
		Repository: "myorg-repo1",
		Branch:     "main",
		ScannedAt:  ts,
		Findings: []finding{
			{TenetID: "check-BP-1.01", Title: "Branch protection", Result: "pass", Reason: "OK"},
			{TenetID: "check-BP-2.01", Title: "Signed commits", Result: "fail", Reason: "unsigned"},
			{TenetID: "check-BP-3.01", Title: "CODEOWNERS", Result: "pass", Reason: "present"},
		},
		Status: "complete",
	})

	evidence, err := ReadAndConvert(dir)
	require.NoError(t, err)
	require.Len(t, evidence, 3)

	assert.Equal(t, gemara.Passed, evidence[0].Result)
	assert.Equal(t, gemara.Failed, evidence[1].Result)
	assert.Equal(t, gemara.Passed, evidence[2].Result)
}

func TestReadAndConvert_MultipleFiles(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)

	writeResultFile(t, dir, &perRepoResult{
		Repository: "repo1",
		Branch:     "main",
		ScannedAt:  ts,
		Findings: []finding{
			{TenetID: "check-BP-1.01", Result: "pass", Reason: "OK"},
		},
	})
	writeResultFile(t, dir, &perRepoResult{
		Repository: "repo2",
		Branch:     "develop",
		ScannedAt:  ts,
		Findings: []finding{
			{TenetID: "check-BP-1.01", Result: "fail", Reason: "not enabled"},
		},
	})

	evidence, err := ReadAndConvert(dir)
	require.NoError(t, err)
	require.Len(t, evidence, 2)
}

func TestReadAndConvert_SkipsNonJSONFiles(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)

	writeResultFile(t, dir, &perRepoResult{
		Repository: "repo1",
		Branch:     "main",
		ScannedAt:  ts,
		Findings: []finding{
			{TenetID: "check-BP-1.01", Result: "pass", Reason: "OK"},
		},
	})

	// Write a non-JSON file that should be ignored
	require.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Results"), 0600))

	evidence, err := ReadAndConvert(dir)
	require.NoError(t, err)
	require.Len(t, evidence, 1)
}

func TestReadAndConvert_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad.json"), []byte("not json{{{"), 0600))

	_, err := ReadAndConvert(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing result file")
}

func TestReadAndConvert_EmptyFindingsInResult(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)

	writeResultFile(t, dir, &perRepoResult{
		Repository: "repo1",
		Branch:     "main",
		ScannedAt:  ts,
		Findings:   []finding{},
		Status:     "complete",
	})

	evidence, err := ReadAndConvert(dir)
	require.NoError(t, err)
	assert.Empty(t, evidence)
}

func TestConvertResult_CorrectAttributes(t *testing.T) {
	ts := time.Date(2026, 4, 25, 14, 30, 0, 0, time.UTC)
	result := &perRepoResult{
		Repository: "myorg/myrepo",
		Branch:     "release-v2",
		ScannedAt:  ts,
		Findings: []finding{
			{TenetID: "check-BP-5.01", Title: "Require reviews", Result: "pass", Reason: "reviews enforced"},
		},
	}

	evidence := convertResult(result)
	require.Len(t, evidence, 1)

	ev := evidence[0]
	assert.Equal(t, "ampel-BP-5.01-myorg/myrepo-release-v2", ev.Metadata.Id)
	assert.Equal(t, "ampel", ev.Metadata.Author.Name)
	assert.Equal(t, gemara.Software, ev.Metadata.Author.Type)
	assert.Equal(t, "BP-5.01", ev.Requirement.EntryId)
	assert.Equal(t, "BP-5.01", ev.Plan.EntryId)
	assert.Equal(t, gemara.Passed, ev.Result)
	assert.Equal(t, "reviews enforced", ev.Message)
	assert.Equal(t, gemara.Datetime(ts.Format(time.RFC3339)), ev.End)
}

func TestConvertResult_TenetIDWithoutPrefix(t *testing.T) {
	result := &perRepoResult{
		Repository: "repo",
		Branch:     "main",
		ScannedAt:  time.Now(),
		Findings: []finding{
			{TenetID: "BP-1.01", Result: "pass"},
		},
	}

	evidence := convertResult(result)
	require.Len(t, evidence, 1)
	// TrimPrefix("BP-1.01", "check-") returns "BP-1.01" unchanged
	assert.Equal(t, "BP-1.01", evidence[0].Requirement.EntryId)
}

func TestMapResult(t *testing.T) {
	tests := []struct {
		input    string
		expected gemara.Result
	}{
		{"pass", gemara.Passed},
		{"fail", gemara.Failed},
		{"unknown", gemara.Unknown},
		{"error", gemara.Unknown},
		{"", gemara.Unknown},
		{"something-else", gemara.Unknown},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, mapResult(tt.input))
		})
	}
}

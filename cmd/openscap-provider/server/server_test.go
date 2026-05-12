// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/antchfx/xmlquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/complytime/complyctl/pkg/provider"
	"github.com/complytime/complytime-providers/cmd/openscap-provider/config"
	"github.com/complytime/complytime-providers/cmd/openscap-provider/xccdf"
)

func TestMapResultStatus(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedResult provider.Result
		expectedError  error
	}{
		{"pass", "pass", provider.ResultPassed, nil},
		{"fixed", "fixed", provider.ResultPassed, nil},
		{"fail", "fail", provider.ResultFailed, nil},
		{"error", "error", provider.ResultError, nil},
		{"unknown", "unknown", provider.ResultError, nil},
		{"invalid", "invalid", provider.ResultError, errors.New("couldn't match invalid")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := mapResultStatus(tt.input)
			assert.Equal(t, tt.expectedResult, result)
			if tt.expectedError != nil {
				assert.EqualError(t, err, tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestParseCheck(t *testing.T) {
	tests := []struct {
		name           string
		xmlContent     string
		expectedResult string
		expectedError  error
	}{
		{
			name:           "Valid/ExpectedFormat",
			xmlContent:     `<check-content-ref name="oval:ssg-audit_perm_change_success:def:1"/>`,
			expectedResult: "audit_perm_change_success",
		},
		{
			name:           "Invalid/UnexpectedFormat",
			xmlContent:     `<check-content-ref name="ovalssg-audit_perm_change_success:def:1"/>`,
			expectedResult: "",
			expectedError:  errors.New("check id \"ovalssg-audit_perm_change_success:def:1\" is in unexpected format"),
		},
		{
			name:           "Invalid/NoNameAttribute",
			xmlContent:     `<check-content-ref/>`,
			expectedResult: "",
			expectedError:  errors.New("check-content-ref node has no 'name' attribute"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node, err := xmlquery.Parse(strings.NewReader(tt.xmlContent))
			assert.NoError(t, err)
			check, err := xccdf.ParseCheck(node.SelectElement("check-content-ref"))
			assert.Equal(t, tt.expectedResult, check)
			if tt.expectedError != nil {
				assert.EqualError(t, err, tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProviderServer_Describe(t *testing.T) {
	s := New()
	resp, err := s.Describe(context.Background(), &provider.DescribeRequest{})
	require.NoError(t, err)
	assert.True(t, resp.Healthy)
	assert.Equal(t, "0.1.0", resp.Version)
	assert.Contains(t, resp.RequiredTargetVariables, "profile")
}

func TestProviderServer_Describe_SupportsExport(t *testing.T) {
	s := New()
	resp, err := s.Describe(context.Background(), &provider.DescribeRequest{})
	require.NoError(t, err)
	assert.True(t, resp.SupportsExport)
}

func TestProviderServer_Generate_NoConfig(t *testing.T) {
	s := New()
	resp, err := s.Generate(context.Background(), &provider.GenerateRequest{})
	require.NoError(t, err)
	assert.False(t, resp.Success)
	assert.Contains(t, resp.ErrorMessage, "no assessment configurations")
}

func TestProviderServer_Scan_NoTargets(t *testing.T) {
	s := New()
	_, err := s.Scan(context.Background(), &provider.ScanRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no targets")
}

func TestParseARFFile_Missing(t *testing.T) {
	_, err := xccdf.ParseARFFile("/nonexistent/arf.xml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open ARF")
}

func TestParseARFFile_InvalidXML(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "arf.xml")
	require.NoError(t, os.WriteFile(tmp, []byte("not xml <<<<"), 0600))
	_, err := xccdf.ParseARFFile(tmp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse ARF")
}

func TestParseARFFile_Valid(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "arf.xml")
	require.NoError(t, os.WriteFile(tmp, []byte("<root><target>host</target></root>"), 0600))
	node, err := xccdf.ParseARFFile(tmp)
	require.NoError(t, err)
	assert.NotNil(t, node)
}

func TestBuildAssessmentsFromARF_NoTarget(t *testing.T) {
	xml := `<root><ds:component xmlns:ds="http://scap.nist.gov/schema/scap/source/1.2">
		<xccdf-1.2:Benchmark xmlns:xccdf-1.2="http://checklists.nist.gov/xccdf/1.2"></xccdf-1.2:Benchmark>
		</ds:component></root>`
	node, err := xmlquery.Parse(strings.NewReader(xml))
	require.NoError(t, err)
	_, err = buildAssessmentsFromARF(node)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no 'target' attribute")
}

func TestBuildAssessmentsFromARF_NoResults(t *testing.T) {
	xml := `<root>
		<target>host1</target>
		<ds:component xmlns:ds="http://scap.nist.gov/schema/scap/source/1.2">
		<xccdf-1.2:Benchmark xmlns:xccdf-1.2="http://checklists.nist.gov/xccdf/1.2"></xccdf-1.2:Benchmark>
		</ds:component></root>`
	node, err := xmlquery.Parse(strings.NewReader(xml))
	require.NoError(t, err)
	assessments, err := buildAssessmentsFromARF(node)
	require.NoError(t, err)
	assert.Empty(t, assessments)
}

func TestFindOVALCheckContentRef_NoChecks(t *testing.T) {
	node, err := xmlquery.Parse(strings.NewReader("<rule></rule>"))
	require.NoError(t, err)
	ref := xccdf.FindOVALCheckContentRef(node.SelectElement("rule"))
	assert.Nil(t, ref)
}

func TestMergeVariables(t *testing.T) {
	global := map[string]string{"a": "1", "b": "2"}
	target := map[string]string{"b": "override", "c": "3"}
	merged := mergeVariables(global, target)
	assert.Equal(t, "1", merged["a"])
	assert.Equal(t, "override", merged["b"])
	assert.Equal(t, "3", merged["c"])
}

// --- Export tests ---

// setupExportServer creates a temp directory, changes to it, sets up the
// workspace directory structure, and returns a ProviderServer.
func setupExportServer(t *testing.T) (*ProviderServer, string) {
	t.Helper()
	dir := t.TempDir()

	origWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(origWd) })

	require.NoError(t, config.EnsureDirectories())

	return New(), dir
}

// writeTestARF writes a minimal ARF XML document to the standard ARF path.
func writeTestARF(t *testing.T, ruleResults string) {
	t.Helper()
	arf := `<?xml version="1.0" encoding="utf-8"?>
<root xmlns:ds="http://scap.nist.gov/schema/scap/source/1.2"
      xmlns:xccdf-1.2="http://checklists.nist.gov/xccdf/1.2">
  <ds:component>
    <xccdf-1.2:Benchmark>
      <xccdf-1.2:Rule id="xccdf_org.ssgproject.content_rule_audit_perm_change_success">
        <xccdf-1.2:title>Record successful permission changes</xccdf-1.2:title>
        <xccdf-1.2:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
          <xccdf-1.2:check-content-ref name="oval:ssg-audit_perm_change_success:def:1"/>
        </xccdf-1.2:check>
      </xccdf-1.2:Rule>
      <xccdf-1.2:Rule id="xccdf_org.ssgproject.content_rule_sshd_disable_root_login">
        <xccdf-1.2:title>Disable SSH root login</xccdf-1.2:title>
        <xccdf-1.2:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
          <xccdf-1.2:check-content-ref name="oval:ssg-sshd_disable_root_login:def:1"/>
        </xccdf-1.2:check>
      </xccdf-1.2:Rule>
    </xccdf-1.2:Benchmark>
  </ds:component>
  <TestResult>
    ` + ruleResults + `
  </TestResult>
</root>`
	require.NoError(t, os.WriteFile(config.ARFPath, []byte(arf), 0600))
}

func TestExport_MissingARFFile(t *testing.T) {
	s, _ := setupExportServer(t)

	resp, err := s.Export(context.Background(), &provider.ExportRequest{
		Collector: provider.CollectorConfig{
			Endpoint: "localhost:4317",
		},
	})
	require.NoError(t, err)
	assert.False(t, resp.Success)
	assert.Contains(t, resp.ErrorMessage, "ARF file not found")
}

func TestExport_NoRuleResults(t *testing.T) {
	s, _ := setupExportServer(t)
	writeTestARF(t, "") // ARF with no rule-results

	resp, err := s.Export(context.Background(), &provider.ExportRequest{
		Collector: provider.CollectorConfig{
			Endpoint: "localhost:4317",
		},
	})
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, int32(0), resp.ExportedCount)
	assert.Equal(t, int32(0), resp.FailedCount)
}

func TestExport_WithResults(t *testing.T) {
	s, _ := setupExportServer(t)
	writeTestARF(t, `
    <rule-result idref="xccdf_org.ssgproject.content_rule_audit_perm_change_success">
      <result>pass</result>
    </rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login">
      <result>fail</result>
    </rule-result>`)

	resp, err := s.Export(context.Background(), &provider.ExportRequest{
		Collector: provider.CollectorConfig{
			Endpoint:  "localhost:4317",
			AuthToken: "test-token",
		},
	})
	require.NoError(t, err)
	// OTLP exporter connects asynchronously; Log calls succeed even without
	// a real collector — the batch processor buffers records.
	assert.True(t, resp.Success)
	assert.Equal(t, int32(2), resp.ExportedCount)
	assert.Equal(t, int32(0), resp.FailedCount)
	assert.Empty(t, resp.ErrorMessage)
}

func TestExport_MalformedARF(t *testing.T) {
	s, _ := setupExportServer(t)

	// Write invalid XML to the ARF path
	require.NoError(t, os.WriteFile(config.ARFPath, []byte("not valid xml <<<<"), 0600))

	resp, err := s.Export(context.Background(), &provider.ExportRequest{
		Collector: provider.CollectorConfig{
			Endpoint: "localhost:4317",
		},
	})
	require.NoError(t, err)
	assert.False(t, resp.Success)
	assert.Contains(t, resp.ErrorMessage, "reading scan results")
}

func TestExport_SkipsNotselectedResults(t *testing.T) {
	s, _ := setupExportServer(t)
	writeTestARF(t, `
    <rule-result idref="xccdf_org.ssgproject.content_rule_audit_perm_change_success">
      <result>pass</result>
    </rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login">
      <result>notselected</result>
    </rule-result>`)

	resp, err := s.Export(context.Background(), &provider.ExportRequest{
		Collector: provider.CollectorConfig{
			Endpoint: "localhost:4317",
		},
	})
	require.NoError(t, err)
	assert.True(t, resp.Success)
	// Only 1 result exported — notselected is skipped
	assert.Equal(t, int32(1), resp.ExportedCount)
}

func TestRuleResultMessage(t *testing.T) {
	tests := []struct {
		name       string
		ruleXML    string
		resultXML  string
		resultText string
		contains   string
	}{
		{
			name:       "TitleAndMessage",
			ruleXML:    `<rule xmlns:xccdf-1.2="http://checklists.nist.gov/xccdf/1.2"><xccdf-1.2:title>My Rule</xccdf-1.2:title></rule>`,
			resultXML:  `<rule-result><message>check failed</message></rule-result>`,
			resultText: "fail",
			contains:   "My Rule",
		},
		{
			name:       "NoTitleNoMessage",
			ruleXML:    `<rule></rule>`,
			resultXML:  `<rule-result></rule-result>`,
			resultText: "pass",
			contains:   "openscap rule-result is pass",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleNode, err := xmlquery.Parse(strings.NewReader(tt.ruleXML))
			require.NoError(t, err)
			resultNode, err := xmlquery.Parse(strings.NewReader(tt.resultXML))
			require.NoError(t, err)
			msg := xccdf.RuleResultMessage(ruleNode.SelectElement("rule"), resultNode.SelectElement("rule-result"), tt.resultText)
			assert.Contains(t, msg, tt.contains)
		})
	}
}

func TestExportErrorMessage(t *testing.T) {
	assert.Equal(t, "", exportErrorMessage(0))
	assert.Equal(t, "3 evidence records failed to export", exportErrorMessage(3))
}

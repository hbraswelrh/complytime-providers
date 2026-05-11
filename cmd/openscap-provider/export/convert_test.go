// SPDX-License-Identifier: Apache-2.0

package export

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// minimalARF builds a minimal ARF XML document with the structure expected
// by NewRuleHashTable and the rule-result query. The Benchmark provides Rule
// definitions (with OVAL check references), and the TestResult provides
// rule-result elements referencing those rules.
func minimalARF(ruleResults string) string {
	return `<?xml version="1.0" encoding="utf-8"?>
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
}

func writeARFFile(t *testing.T, dir string, content string) string {
	t.Helper()
	path := filepath.Join(dir, "arf-results.xml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	return path
}

func TestReadAndConvert_PassedRule(t *testing.T) {
	dir := t.TempDir()
	arf := minimalARF(`
    <rule-result idref="xccdf_org.ssgproject.content_rule_audit_perm_change_success">
      <result>pass</result>
    </rule-result>`)
	path := writeARFFile(t, dir, arf)

	evidence, err := ReadAndConvert(path)
	require.NoError(t, err)
	require.Len(t, evidence, 1)

	ev := evidence[0]
	assert.Equal(t, "openscap", ev.Metadata.Author.Name)
	assert.Equal(t, gemara.Software, ev.Metadata.Author.Type)
	assert.Equal(t, "audit_perm_change_success", ev.Requirement.EntryId)
	assert.Equal(t, "xccdf_org.ssgproject.content_rule_audit_perm_change_success", ev.Plan.EntryId)
	assert.Equal(t, gemara.Passed, ev.Result)
	assert.Equal(t, "openscap-audit_perm_change_success-xccdf_org.ssgproject.content_rule_audit_perm_change_success", ev.Metadata.Id)
	assert.Contains(t, ev.Message, "Record successful permission changes")
}

func TestReadAndConvert_FailedRule(t *testing.T) {
	dir := t.TempDir()
	arf := minimalARF(`
    <rule-result idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login">
      <result>fail</result>
      <message>Root login is currently enabled</message>
    </rule-result>`)
	path := writeARFFile(t, dir, arf)

	evidence, err := ReadAndConvert(path)
	require.NoError(t, err)
	require.Len(t, evidence, 1)

	ev := evidence[0]
	assert.Equal(t, gemara.Failed, ev.Result)
	assert.Equal(t, "sshd_disable_root_login", ev.Requirement.EntryId)
	assert.Contains(t, ev.Message, "Root login is currently enabled")
}

func TestReadAndConvert_SkipsNotselected(t *testing.T) {
	dir := t.TempDir()
	arf := minimalARF(`
    <rule-result idref="xccdf_org.ssgproject.content_rule_audit_perm_change_success">
      <result>notselected</result>
    </rule-result>`)
	path := writeARFFile(t, dir, arf)

	evidence, err := ReadAndConvert(path)
	require.NoError(t, err)
	assert.Empty(t, evidence)
}

func TestReadAndConvert_SkipsNotapplicable(t *testing.T) {
	dir := t.TempDir()
	arf := minimalARF(`
    <rule-result idref="xccdf_org.ssgproject.content_rule_audit_perm_change_success">
      <result>notapplicable</result>
    </rule-result>`)
	path := writeARFFile(t, dir, arf)

	evidence, err := ReadAndConvert(path)
	require.NoError(t, err)
	assert.Empty(t, evidence)
}

func TestReadAndConvert_MultipleRules(t *testing.T) {
	dir := t.TempDir()
	arf := minimalARF(`
    <rule-result idref="xccdf_org.ssgproject.content_rule_audit_perm_change_success">
      <result>pass</result>
    </rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login">
      <result>fail</result>
    </rule-result>`)
	path := writeARFFile(t, dir, arf)

	evidence, err := ReadAndConvert(path)
	require.NoError(t, err)
	require.Len(t, evidence, 2)

	assert.Equal(t, gemara.Passed, evidence[0].Result)
	assert.Equal(t, gemara.Failed, evidence[1].Result)
}

func TestReadAndConvert_MixedSkippedAndActive(t *testing.T) {
	dir := t.TempDir()
	arf := minimalARF(`
    <rule-result idref="xccdf_org.ssgproject.content_rule_audit_perm_change_success">
      <result>pass</result>
    </rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login">
      <result>notselected</result>
    </rule-result>`)
	path := writeARFFile(t, dir, arf)

	evidence, err := ReadAndConvert(path)
	require.NoError(t, err)
	require.Len(t, evidence, 1)
	assert.Equal(t, "audit_perm_change_success", evidence[0].Requirement.EntryId)
}

func TestReadAndConvert_FixedResult(t *testing.T) {
	dir := t.TempDir()
	arf := minimalARF(`
    <rule-result idref="xccdf_org.ssgproject.content_rule_audit_perm_change_success">
      <result>fixed</result>
    </rule-result>`)
	path := writeARFFile(t, dir, arf)

	evidence, err := ReadAndConvert(path)
	require.NoError(t, err)
	require.Len(t, evidence, 1)
	assert.Equal(t, gemara.Passed, evidence[0].Result)
}

func TestReadAndConvert_ErrorResult(t *testing.T) {
	dir := t.TempDir()
	arf := minimalARF(`
    <rule-result idref="xccdf_org.ssgproject.content_rule_audit_perm_change_success">
      <result>error</result>
    </rule-result>`)
	path := writeARFFile(t, dir, arf)

	evidence, err := ReadAndConvert(path)
	require.NoError(t, err)
	require.Len(t, evidence, 1)
	assert.Equal(t, gemara.Unknown, evidence[0].Result)
}

func TestReadAndConvert_MissingARFFile(t *testing.T) {
	_, err := ReadAndConvert("/nonexistent/arf.xml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open ARF")
}

func TestReadAndConvert_InvalidXML(t *testing.T) {
	dir := t.TempDir()
	path := writeARFFile(t, dir, "not xml <<<<")

	_, err := ReadAndConvert(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse ARF")
}

func TestReadAndConvert_NoRuleResults(t *testing.T) {
	dir := t.TempDir()
	arf := minimalARF("") // no rule-results
	path := writeARFFile(t, dir, arf)

	evidence, err := ReadAndConvert(path)
	require.NoError(t, err)
	assert.Empty(t, evidence)
}

func TestReadAndConvert_UnknownRuleIDRef(t *testing.T) {
	dir := t.TempDir()
	// Reference a rule that doesn't exist in the Benchmark
	arf := minimalARF(`
    <rule-result idref="xccdf_org.ssgproject.content_rule_nonexistent">
      <result>pass</result>
    </rule-result>`)
	path := writeARFFile(t, dir, arf)

	evidence, err := ReadAndConvert(path)
	require.NoError(t, err)
	// Rule not found in hash table — should be skipped
	assert.Empty(t, evidence)
}

func TestReadAndConvert_AssessmentIDFormat(t *testing.T) {
	dir := t.TempDir()
	arf := minimalARF(`
    <rule-result idref="xccdf_org.ssgproject.content_rule_audit_perm_change_success">
      <result>pass</result>
    </rule-result>`)
	path := writeARFFile(t, dir, arf)

	evidence, err := ReadAndConvert(path)
	require.NoError(t, err)
	require.Len(t, evidence, 1)

	// Assessment ID format: "openscap-<requirementID>-<ruleIDRef>"
	expected := "openscap-audit_perm_change_success-xccdf_org.ssgproject.content_rule_audit_perm_change_success"
	assert.Equal(t, expected, evidence[0].Metadata.Id)
}

func TestMapResultStatus(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected gemara.Result
		wantErr  bool
	}{
		{"pass", "pass", gemara.Passed, false},
		{"fixed", "fixed", gemara.Passed, false},
		{"fail", "fail", gemara.Failed, false},
		{"error", "error", gemara.Unknown, false},
		{"unknown", "unknown", gemara.Unknown, false},
		{"invalid", "invalid", gemara.Unknown, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := mapResultStatus(tt.input)
			assert.Equal(t, tt.expected, result)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

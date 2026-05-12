// SPDX-License-Identifier: Apache-2.0

package export

import (
	"fmt"
	"time"

	"github.com/antchfx/xmlquery"
	"github.com/gemaraproj/go-gemara"

	"github.com/complytime/complybeacon/proofwatch"
	"github.com/complytime/complytime-providers/cmd/openscap-provider/xccdf"
)

const engineName = "openscap"

// ReadAndConvert reads the ARF XML file, parses rule-results, and converts
// each assessment to a GemaraEvidence object.
func ReadAndConvert(arfPath string) ([]proofwatch.GemaraEvidence, error) {
	xmlnode, err := xccdf.ParseARFFile(arfPath)
	if err != nil {
		return nil, err
	}

	ruleTable := xccdf.NewRuleHashTable(xmlnode)
	results := xmlnode.SelectElements("//rule-result")

	var evidence []proofwatch.GemaraEvidence
	now := time.Now()

	for _, result := range results {
		ev, skip, err := convertRuleResult(result, ruleTable, now)
		if err != nil {
			return nil, err
		}
		if !skip {
			evidence = append(evidence, ev)
		}
	}

	return evidence, nil
}

func convertRuleResult(result *xmlquery.Node, ruleTable map[string]*xmlquery.Node, timestamp time.Time) (proofwatch.GemaraEvidence, bool, error) {
	resultEl := result.SelectElement("result")
	if resultEl == nil {
		return proofwatch.GemaraEvidence{}, true, nil
	}
	resultText := resultEl.InnerText()
	if xccdf.IsSkippableResult(resultText) {
		return proofwatch.GemaraEvidence{}, true, nil
	}

	ruleIDRef := result.SelectAttr("idref")
	rule, ok := ruleTable[ruleIDRef]
	if !ok {
		return proofwatch.GemaraEvidence{}, true, nil
	}

	ovalRefEl := xccdf.FindOVALCheckContentRef(rule)
	if ovalRefEl == nil {
		return proofwatch.GemaraEvidence{}, true, nil
	}

	requirementID, err := xccdf.ParseCheck(ovalRefEl)
	if err != nil {
		return proofwatch.GemaraEvidence{}, false, err
	}

	gemaraResult, err := mapResultStatus(resultText)
	if err != nil {
		return proofwatch.GemaraEvidence{}, false, err
	}

	message := xccdf.RuleResultMessage(rule, result, resultText)
	assessmentID := fmt.Sprintf("%s-%s-%s", engineName, requirementID, ruleIDRef)

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
				EntryId: requirementID,
			},
			Plan: &gemara.EntryMapping{
				EntryId: ruleIDRef,
			},
			Result:  gemaraResult,
			Message: message,
			End:     gemara.Datetime(timestamp.Format(time.RFC3339)),
		},
	}

	return ev, false, nil
}

func mapResultStatus(resultText string) (gemara.Result, error) {
	switch resultText {
	case "pass", "fixed":
		return gemara.Passed, nil
	case "fail":
		return gemara.Failed, nil
	case "error", "unknown":
		return gemara.Unknown, nil
	}
	return gemara.Unknown, fmt.Errorf("couldn't match result status %q", resultText)
}

package validations

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-cli-security/utils"
)

type ValidationParams struct {
	// The actual content to verify.
	Actual interface{}
	// If provided, the test will check if the content matches the expected results.
	Expected interface{}
	// If provided, the test will check exact values and not only the minimum values / existence.
	ExactResultsMatch bool

	// Expected counts of values to validate.
	Vulnerabilities       int
	Licenses              int
	SecurityViolations    int
	LicenseViolations     int
	OperationalViolations int
	Applicable            int
	Undetermined          int
	NotCovered            int
	NotApplicable         int
	Sast                  int
	Iac                   int
	Secrets               int
}

type ValidationPair struct {
	Expected interface{}
	Actual   interface{}
	ErrMsg   string
}

func (vp ValidationPair) ErrMsgs(t *testing.T) []string {
	expectedStr := fmt.Sprintf("%v", vp.Expected)
	var err error
	// If the expected value is a struct, convert it to a JSON string.
	if _, ok := vp.Expected.(string); !ok {
		expectedStr, err = utils.GetAsJsonString(vp.Expected)
		assert.NoError(t, err)
	}
	actualStr := fmt.Sprintf("%v", vp.Actual)
	// If the actual value is a struct, convert it to a JSON string.
	if _, ok := vp.Actual.(string); !ok {
		actualStr, err = utils.GetAsJsonString(vp.Actual)
		assert.NoError(t, err)
	}
	return []string{vp.ErrMsg, fmt.Sprintf("\n* Expected:\n%s\n\n* Actual:\n%s\n", expectedStr, actualStr)}
}

func validatePairs(t *testing.T, exactMatch bool, pairs ...ValidationPair) bool {
	for _, pair := range pairs {
		switch pair.Expected.(type) {
		case string:
			if !validateStrContent(t, pair.Expected.(string), pair.Actual.(string), exactMatch, pair.ErrMsgs(t)) {
				return false
			}
		case *interface{}:
			if !validatePointers(t, pair.Expected, pair.Actual, exactMatch, pair.ErrMsgs(t)) {
				return false
			}
		case []interface{}:
			if exactMatch {
				if !assert.ElementsMatch(t, pair.Expected, pair.Actual, pair.ErrMsgs(t)) {
					return false
				}
			} else if !assert.Subset(t, pair.Expected, pair.Actual, pair.ErrMsgs(t)) {
				return false
			}
		default:
			return assert.Equal(t, pair.Expected, pair.Actual, pair.ErrMsgs(t))
		}
	}
	return true
}

func validatePointers(t *testing.T, expected, actual interface{}, actualValue bool, msgAndArgs ...interface{}) bool {
	if actualValue {
		return assert.Equal(t, expected, actual, msgAndArgs...)
	}
	if expected != nil {
		return assert.NotNil(t, actual, msgAndArgs...)
	}
	return assert.Nil(t, actual, msgAndArgs...)
}

func validateStrContent(t *testing.T, expected, actual string, actualValue bool, msgAndArgs ...interface{}) bool {
	if actualValue {
		return assert.Equal(t, expected, actual, msgAndArgs...)
	}
	if expected != "" {
		return assert.NotEmpty(t, actual, msgAndArgs...)
	} else {
		return assert.Empty(t, actual, msgAndArgs...)
	}
}

// func VerifyJsonScanResults(t *testing.T, content string, minViolations, minVulnerabilities, minLicenses int) {
// 	var results []services.ScanResponse
// 	err := json.Unmarshal([]byte(content), &results)
// 	if assert.NoError(t, err) {
// 		var violations []services.Violation
// 		var vulnerabilities []services.Vulnerability
// 		var licenses []services.License
// 		for _, result := range results {
// 			violations = append(violations, result.Violations...)
// 			vulnerabilities = append(vulnerabilities, result.Vulnerabilities...)
// 			licenses = append(licenses, result.Licenses...)
// 		}
// 		assert.True(t, len(violations) >= minViolations, fmt.Sprintf("Expected at least %d violations in scan results, but got %d violations.", minViolations, len(violations)))
// 		assert.True(t, len(vulnerabilities) >= minVulnerabilities, fmt.Sprintf("Expected at least %d vulnerabilities in scan results, but got %d vulnerabilities.", minVulnerabilities, len(vulnerabilities)))
// 		assert.True(t, len(licenses) >= minLicenses, fmt.Sprintf("Expected at least %d Licenses in scan results, but got %d Licenses.", minLicenses, len(licenses)))
// 	}
// }

// func VerifySimpleJsonScanResults(t *testing.T, content string, minViolations, minVulnerabilities, minLicenses int) {
// 	var results formats.SimpleJsonResults
// 	err := json.Unmarshal([]byte(content), &results)
// 	if assert.NoError(t, err) {
// 		assert.GreaterOrEqual(t, len(results.SecurityViolations), minViolations)
// 		assert.GreaterOrEqual(t, len(results.Vulnerabilities), minVulnerabilities)
// 		assert.GreaterOrEqual(t, len(results.Licenses), minLicenses)
// 	}
// }
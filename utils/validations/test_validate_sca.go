package validations

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/stretchr/testify/assert"
)

// Validation on SCA content only (No JAS in this content), with the option to provide expected results.
// Content should be a Json string of slice of []services.ScanResponse and will be unmarshal.
// Value is set as the Actual content in the validation params
func VerifyJsonResults(t *testing.T, content string, params ValidationParams) {
	var results []services.ScanResponse
	err := json.Unmarshal([]byte(content), &results)
	assert.NoError(t, err)
	params.Actual = results
	ValidateCommandJsonOutput(t, params)
}

// Validation on SCA content only (No JAS in this content)
// Actual (and optional Expected) content should be a slice of services.ScanResponse in the validation params
func ValidateCommandJsonOutput(t *testing.T, params ValidationParams) {
	results, ok := params.Actual.([]services.ScanResponse)
	if assert.True(t, ok) {
		ValidateScanResponseIssuesCount(t, params, results...)
		if params.Expected != nil {
			expectedResults, ok := params.Expected.([]services.ScanResponse)
			if assert.True(t, ok) {
				ValidateScanResponses(t, params.ExactResultsMatch, expectedResults, results)
			}
		}
	}
}

func ValidateScanResponseIssuesCount(t *testing.T, params ValidationParams, content ...services.ScanResponse) {
	var vulnerabilities []services.Vulnerability
	var licenses []services.License
	var securityViolations []services.Violation
	var licenseViolations []services.Violation
	var operationalViolations []services.Violation
	for _, result := range content {
		vulnerabilities = append(vulnerabilities, result.Vulnerabilities...)
		licenses = append(licenses, result.Licenses...)
		for _, violation := range result.Violations {
			switch violation.ViolationType {
			case formats.ViolationTypeSecurity.String():
				securityViolations = append(securityViolations, violation)
			case formats.ViolationTypeLicense.String():
				licenseViolations = append(licenseViolations, violation)
			case formats.ViolationTypeOperationalRisk.String():
				operationalViolations = append(operationalViolations, violation)
			}
		}
	}
	if params.ExactResultsMatch {
		assert.Equal(t, params.Vulnerabilities, len(vulnerabilities), fmt.Sprintf("Expected %d vulnerabilities in scan responses, but got %d vulnerabilities.", params.Vulnerabilities, len(vulnerabilities)))
		assert.Equal(t, params.Licenses, len(licenses), fmt.Sprintf("Expected %d Licenses in scan responses, but got %d Licenses.", params.Licenses, len(licenses)))
		assert.Equal(t, params.SecurityViolations, len(securityViolations), fmt.Sprintf("Expected %d security violations in scan responses, but got %d security violations.", params.SecurityViolations, len(securityViolations)))
		assert.Equal(t, params.LicenseViolations, len(licenseViolations), fmt.Sprintf("Expected %d license violations in scan responses, but got %d license violations.", params.LicenseViolations, len(licenseViolations)))
		assert.Equal(t, params.OperationalViolations, len(operationalViolations), fmt.Sprintf("Expected %d operational risk violations in scan responses, but got %d operational risk violations.", params.OperationalViolations, len(operationalViolations)))
	} else {
		assert.GreaterOrEqual(t, len(vulnerabilities), params.Vulnerabilities, fmt.Sprintf("Expected at least %d vulnerabilities in scan responses, but got %d vulnerabilities.", params.Vulnerabilities, len(vulnerabilities)))
		assert.GreaterOrEqual(t, len(licenses), params.Licenses, fmt.Sprintf("Expected at least %d Licenses in scan responses, but got %d Licenses.", params.Licenses, len(licenses)))
		assert.GreaterOrEqual(t, len(securityViolations), params.SecurityViolations, fmt.Sprintf("Expected at least %d security violations in scan responses, but got %d security violations.", params.LicenseViolations, len(securityViolations)))
		assert.GreaterOrEqual(t, len(licenseViolations), params.LicenseViolations, fmt.Sprintf("Expected at least %d license violations in scan responses, but got %d license violations.", params.LicenseViolations, len(licenseViolations)))
		assert.GreaterOrEqual(t, len(operationalViolations), params.OperationalViolations, fmt.Sprintf("Expected at least %d operational risk violations in scan responses, but got %d operational risk violations.", params.OperationalViolations, len(operationalViolations)))
	}
}

func ValidateScanResponses(t *testing.T, exactMatch bool, expected, actual []services.ScanResponse) {
	for _, expectedResponse := range expected {
		actualResponse := getScanResponseByScanId(expectedResponse.ScanId, actual)
		if !assert.NotNil(t, actualResponse, fmt.Sprintf("ScanId %s not found in the scan responses", expectedResponse.ScanId)) {
			return
		}
	}
}

func getScanResponseByScanId(scanId string, content []services.ScanResponse) *services.ScanResponse {
	for _, result := range content {
		if result.ScanId == scanId {
			return &result
		}
	}
	return nil
}
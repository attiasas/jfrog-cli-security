package enrich

import (
	"fmt"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	clientUtils "github.com/jfrog/jfrog-client-go/utils"

	"github.com/jfrog/jfrog-cli-security/sca/runner"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/catalog"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdx"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

type EnrichScanParams struct {
	ServerDetails *config.ServerDetails
	ProjectKey    string
}

type EnrichScanStrategy struct {
	EnrichScanParams
	threadId int
}

func copy(sgs *EnrichScanStrategy) *EnrichScanStrategy {
	return &EnrichScanStrategy{
		EnrichScanParams: sgs.EnrichScanParams,
	}
}

func (ess *EnrichScanStrategy) Parallel(threadId int) runner.SbomScanStrategy {
	instance := copy(ess)
	ess.threadId = threadId
	return instance
}

func (ess *EnrichScanStrategy) ScaScanTask(target *cyclonedx.BOM) (response services.ScanResponse, err error) {
	catalogManager, err := catalog.CreateCatalogServiceManager(ess.ServerDetails, catalog.WithScopedProjectKey(ess.ProjectKey))
	if err != nil {
		return services.ScanResponse{}, fmt.Errorf("failed to create catalog service manager: %w", err)
	}
	log.Info(fmt.Sprintf("%s Enriching BOM with %d library components...", clientUtils.GetLogMsgPrefix(ess.threadId, false), len(cdx.GetLibraryComponentRefs(target))))

	enriched, err := catalogManager.Enrich(target)
	if err != nil {
		return services.ScanResponse{}, fmt.Errorf("failed to enrich BOM: %w", err)
	}
	vulnerabilities := 0
	if enriched.Vulnerabilities != nil {
		vulnerabilities = len(*enriched.Vulnerabilities)
	}
	log.Info(utils.GetScanFindingsLog(utils.ScaScan, vulnerabilities, 0, ess.threadId))
	if str, e := utils.GetAsJsonString(enriched, true, true); e == nil {
		log.Debug(fmt.Sprintf("%s Enriched BOM: %s", clientUtils.GetLogMsgPrefix(ess.threadId, false), str))
	}
	response = toScanResponse(enriched)
	log.Info(fmt.Sprintf("%s Finished '%s' enrich. %s", clientUtils.GetLogMsgPrefix(ess.threadId, false), services.Dependency, utils.GetScanFindingsLog(utils.ScaScan, len(response.Vulnerabilities), len(response.Violations), -1)))
	return
}

func toScanResponse(enriched *cyclonedx.BOM) services.ScanResponse {
	scanResponse := services.ScanResponse{}
	if enriched.Vulnerabilities != nil {
		for _, vulnerability := range *enriched.Vulnerabilities {
			cves := []services.Cve{
				{Id: vulnerability.BOMRef},
			}
			if vulnerability.Affects != nil {
				for _, affect := range *vulnerability.Affects {
					scanResponse.Vulnerabilities = append(scanResponse.Vulnerabilities, services.Vulnerability{
						Components: map[string]services.Component{
							cdx.PurlToXrayComponentId(affect.Ref): {},
						},
						Cves:     cves,
						Severity: getSeverity(vulnerability),
						IssueId:  vulnerability.ID,
					})
				}
			}
		}
	}
	return scanResponse
}

func getSeverity(vulnerability cyclonedx.Vulnerability) string {
	if vulnerability.Ratings == nil || len(*vulnerability.Ratings) == 0 {
		return severityutils.Unknown.String()
	}
	// Convert the ratings to severities
	severities := []severityutils.Severity{}
	for _, rating := range *vulnerability.Ratings {
		severities = append(severities, severityutils.CycloneDxSeverityToSeverity(rating.Severity))
	}
	// Get the most severe rating
	return severityutils.MostSevereSeverity(severities...).String()

}

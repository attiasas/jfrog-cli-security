package catalog

import (
	"fmt"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/sca/runner"

	"github.com/jfrog/jfrog-cli-security/utils/xray"
	clientUtils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

type JfrogCatalogEnricherStrategy struct {
	serverDetails *config.ServerDetails
	threadId      int
}

func copy(sgs *JfrogCatalogEnricherStrategy) *JfrogCatalogEnricherStrategy {
	return &JfrogCatalogEnricherStrategy{
		serverDetails: sgs.serverDetails,
		threadId:      sgs.threadId,
	}
}

func (sgs *JfrogCatalogEnricherStrategy) SetServerDetails(serverDetails *config.ServerDetails) runner.SbomScanStrategy {
	sgs.serverDetails = serverDetails
	return sgs
}

func (sgs *JfrogCatalogEnricherStrategy) Parallel(threadId int) runner.SbomScanStrategy {
	instance := copy(sgs)
	instance.threadId = threadId
	return instance
}

func (sgs *JfrogCatalogEnricherStrategy) ScaScanTask(target *cyclonedx.BOM) (techResults services.ScanResponse, err error) {
	defer func() {
		if err == nil {
			log.Info(fmt.Sprintf(
				"%s Finished '%s' catalog enrichment.",
				clientUtils.GetLogMsgPrefix(sgs.threadId, false),
			))
		}
		return
	}()

	xm, err := xray.CreateXrayServiceManager(sgs.serverDetails)
	if err != nil {
		return services.ScanResponse{}, fmt.Errorf("failed to create Xray service manager: %w", err)
	}

	es := NewEnrichService(xm.Client())
	es.XrayDetails = xm.Config().GetServiceDetails()
	enriched, err := es.EnrichCycloneDX(target)
	if err != nil {
		return services.ScanResponse{}, fmt.Errorf("failed to enrich CycloneDX SBOM: %w", err)
	}

	*target = *enriched

	return services.ScanResponse{}, nil
}

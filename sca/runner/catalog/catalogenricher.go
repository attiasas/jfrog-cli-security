package catalog

import (
	"fmt"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/sca/runner"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdx"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/xray"
	"github.com/jfrog/jfrog-cli-security/utils/xray/scangraph"

	clientUtils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xrayClientUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

type JfrogCatalogEnricherStrategy struct {
	threadId int
}

func copy(sgs *JfrogCatalogEnricherStrategy) *JfrogCatalogEnricherStrategy {
	return &JfrogCatalogEnricherStrategy{
		threadId: sgs.threadId,
	}
}

func (sgs *JfrogCatalogEnricherStrategy) WithParams(params *scangraph.ScanGraphParams) runner.SbomScanStrategy {
	instance := copy(sgs)
	return instance
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

	return
}

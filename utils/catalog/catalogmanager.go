package catalog

import (
	// clientconfig "github.com/jfrog/jfrog-client-go/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	// "github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
)

func CreateCatalogServiceManager(serverDetails *config.ServerDetails) {
	// certsPath, err := coreutils.GetJfrogCertsDir()
	// if err != nil {
	// 	return
	// }
	// xrayDetails, err := serverDetails.CreateXrayAuthConfig()
	// if err != nil {
	// 	return
	// }
	// serviceConfig, err := clientconfig.NewConfigBuilder().
	// 	SetServiceDetails(xrayDetails).
	// 	SetCertificatesPath(certsPath).
	// 	SetInsecureTls(serverDetails.InsecureTls).
	// 	Build()
	// if err != nil {
	// 	return
	// }
	// manager, err = xray.New(serviceConfig)
	// if err != nil {
	// 	return nil, err
	// }
	// for _, option := range options {
	// 	option(manager)
	// }
	return
}

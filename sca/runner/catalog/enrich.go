package catalog

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-client-go/auth"
	"github.com/jfrog/jfrog-client-go/http/jfroghttpclient"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
)

// EnrichService returns the https client and Xray details
type EnrichService struct {
	client      *jfroghttpclient.JfrogHttpClient
	XrayDetails auth.ServiceDetails
}

// NewEnrich creates a new service to retrieve the version of Xray
func NewEnrichService(client *jfroghttpclient.JfrogHttpClient) *EnrichService {
	return &EnrichService{client: client}
}

// GetXrayDetails returns the Xray details
func (es *EnrichService) GetXrayDetails() auth.ServiceDetails {
	return es.XrayDetails
}

// GetVersion returns the version of Xray
func (es *EnrichService) EnrichCycloneDX(bom *cyclonedx.BOM) (*cyclonedx.BOM, error) {
	httpDetails := es.XrayDetails.CreateHttpClientDetails()
	httpDetails.SetContentTypeApplicationJson()

	var buf bytes.Buffer
	var writer io.Writer = &buf
	encoder := cyclonedx.NewBOMEncoder(writer, cyclonedx.BOMFileFormatJSON)
	err := encoder.Encode(bom)
	if err != nil {
		return &cyclonedx.BOM{}, errorutils.CheckErrorf("couldn't encode CycloneDX BOM: " + err.Error())
	}

	requestBody := buf.Bytes()
	url := es.XrayDetails.GetUrl()
	url = strings.TrimSuffix(url, "/xray/") + "/catalog/api/v1/beta/cyclonedx/enrich"
	resp, body, err := es.client.SendPost(url, requestBody, &httpDetails)
	if err != nil {
		return &cyclonedx.BOM{}, errors.New("failed while attempting to get JFrog Xray version: " + err.Error())
	}
	if err = errorutils.CheckResponseStatusWithBody(resp, body, http.StatusOK); err != nil {
		return &cyclonedx.BOM{}, errors.New("got unexpected server response while attempting to get JFrog Xray version:\n" + err.Error())
	}

	reader := bytes.NewReader(body)
	decoder := cyclonedx.NewBOMDecoder(reader, cyclonedx.BOMFileFormatJSON)
	var enriched cyclonedx.BOM
	if err = decoder.Decode(&enriched); err != nil {
		return &cyclonedx.BOM{}, errorutils.CheckErrorf("couldn't parse JFrog Xray server version response: " + err.Error())
	}

	return &enriched, nil
}

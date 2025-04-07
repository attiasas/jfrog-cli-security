package cdx

// import (
// 	"testing"
// 	"github.com/stretchr/testify/assert"
// 	"github.com/CycloneDX/cyclonedx-go"

// 	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
// )

// func TestDepTreeToSbom(t *testing.T) {
// 	tests := []struct {
// 		name         string
// 		depTrees     []*xrayUtils.GraphNode
// 		expectedSbom *cyclonedx.BOM
// 	}{
// 		{
// 			name:         "no deps",
// 			depTrees:     []*xrayUtils.GraphNode{},
// 			expectedSbom: cyclonedx.NewBOM(),
// 		},
// 		{
// 			name: "one tree with one node",
// 			depTrees: []*xrayUtils.GraphNode{
// 				{
// 					Id:    "root",
// 					Nodes: []*xrayUtils.GraphNode{{Id: "npm://A:1.0.1"}},
// 				},
// 			},
// 			expectedSbom: Sbom{
// 				Components: []SbomEntry{
// 					{
// 						Name: "A", Version: "1.0.1", Type: "npm", Direct: true,
// 					},
// 				},
// 			},
// 		},
// 		{
// 			name: "one tree with multiple nodes",
// 			depTrees: []*xrayCmdUtils.GraphNode{
// 				{
// 					Id: "root",
// 					Nodes: []*xrayCmdUtils.GraphNode{
// 						{
// 							Id:    "npm://A:1.0.1",
// 							Nodes: []*xrayCmdUtils.GraphNode{{Id: "npm://B:1.0.0"}, {Id: "npm://C:1.0.1"}},
// 						},
// 						{
// 							Id:    "npm://D:2.0.0",
// 							Nodes: []*xrayCmdUtils.GraphNode{{Id: "npm://C:1.0.1"}},
// 						},
// 						{
// 							Id: "npm://B:1.0.0",
// 						},
// 					},
// 				},
// 			},
// 			expectedSbom: Sbom{
// 				Components: []SbomEntry{
// 					{
// 						Name: "A", Version: "1.0.1", Type: "npm", Direct: true,
// 					},
// 					{
// 						Name: "B", Version: "1.0.0", Type: "npm", Direct: true,
// 					},
// 					{
// 						Name: "D", Version: "2.0.0", Type: "npm", Direct: true,
// 					},
// 					{
// 						Name: "C", Version: "1.0.1", Type: "npm", Direct: false,
// 					},
// 				},
// 			},
// 		},
// 		{
// 			name: "multiple trees",
// 			depTrees: []*xrayCmdUtils.GraphNode{
// 				{
// 					Id: "root",
// 					Nodes: []*xrayCmdUtils.GraphNode{
// 						{
// 							Id:    "npm://A:1.0.1",
// 							Nodes: []*xrayCmdUtils.GraphNode{{Id: "go://B:1.0.0"}},
// 						},
// 						{
// 							Id: "npm://C:1.0.1",
// 						},
// 						{
// 							Id: "npm://D:1.0.0",
// 						},
// 					},
// 				},
// 				{
// 					Id: "root",
// 					Nodes: []*xrayCmdUtils.GraphNode{
// 						{
// 							Id:    "npm://A:2.0.1",
// 							Nodes: []*xrayCmdUtils.GraphNode{{Id: "npm://B:1.0.0"}, {Id: "npm://C:1.0.1"}, {Id: "npm://D:1.2.3"}},
// 						},
// 					},
// 				},
// 			},
// 			expectedSbom: Sbom{
// 				Components: []SbomEntry{
// 					{
// 						Name: "A", Version: "1.0.1", Type: "npm", Direct: true,
// 					},
// 					{
// 						Name: "A", Version: "2.0.1", Type: "npm", Direct: true,
// 					},
// 					{
// 						Name: "C", Version: "1.0.1", Type: "npm", Direct: true,
// 					},
// 					{
// 						Name: "D", Version: "1.0.0", Type: "npm", Direct: true,
// 					},
// 					{
// 						Name: "B", Version: "1.0.0", Type: "Go", Direct: false,
// 					},
// 					{
// 						Name: "B", Version: "1.0.0", Type: "npm", Direct: false,
// 					},
// 					{
// 						Name: "D", Version: "1.2.3", Type: "npm", Direct: false,
// 					},
// 				},
// 			},
// 		},
// 	}

// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 			sbom := DepTreeToSbom(test.depTrees)
// 			SortSbom(sbom.Components)
// 			assert.Equal(t, test.expectedSbom, sbom)
// 		})
// 	}
// }

// func TestCompTreeToSbom(t *testing.T) {
// 	tests := []struct {
// 		name         string
// 		compTrees    *xrayCmdUtils.BinaryGraphNode
// 		expectedSbom Sbom
// 	}{
// 		{
// 			name:         "no deps",
// 			compTrees:    &xrayCmdUtils.BinaryGraphNode{},
// 			expectedSbom: Sbom{Components: []SbomEntry{}},
// 		},
// 		{
// 			name: "one tree with one node",
// 			compTrees: &xrayCmdUtils.BinaryGraphNode{
// 				Id:    "root",
// 				Nodes: []*xrayCmdUtils.BinaryGraphNode{{Id: "npm://A:1.0.1"}},
// 			},
// 			expectedSbom: Sbom{
// 				Components: []SbomEntry{
// 					{
// 						Name: "A", Version: "1.0.1", Type: "npm", Direct: true,
// 					},
// 				},
// 			},
// 		},
// 		{
// 			name: "one tree rpm",
// 			compTrees: &xrayCmdUtils.BinaryGraphNode{
// 				Id:    "npm://root:1.0.0",
// 				Nodes: []*xrayCmdUtils.BinaryGraphNode{{Id: "rpm://OS-1:A:1111:1.0.1"}},
// 				Path:  "file.rpm",
// 			},
// 			expectedSbom: Sbom{
// 				Components: []SbomEntry{
// 					{
// 						Name: "root", Version: "1.0.0", Type: "npm", Direct: true,
// 					},
// 					{
// 						Name: "A", Version: "1111:1.0.1", Type: "RPM", Direct: false,
// 					},
// 				},
// 			},
// 		},
// 		{
// 			name: "one tree with multiple nodes",
// 			compTrees: &xrayCmdUtils.BinaryGraphNode{
// 				Id: "root",
// 				Nodes: []*xrayCmdUtils.BinaryGraphNode{
// 					{
// 						Id:    "npm://A:1.0.1",
// 						Nodes: []*xrayCmdUtils.BinaryGraphNode{{Id: "npm://B:1.0.0"}, {Id: "npm://C:1.0.1"}},
// 					},
// 					{
// 						Id:    "npm://D:2.0.0",
// 						Nodes: []*xrayCmdUtils.BinaryGraphNode{{Id: "npm://C:1.0.1"}},
// 					},
// 					{
// 						Id: "npm://B:1.0.0",
// 					},
// 					{
// 						Id: "npm://No-Version",
// 					},
// 				},
// 			},
// 			expectedSbom: Sbom{
// 				Components: []SbomEntry{
// 					{
// 						Name: "A", Version: "1.0.1", Type: "npm", Direct: true,
// 					},
// 					{
// 						Name: "B", Version: "1.0.0", Type: "npm", Direct: true,
// 					},
// 					{
// 						Name: "D", Version: "2.0.0", Type: "npm", Direct: true,
// 					},
// 					{
// 						Name: "C", Version: "1.0.1", Type: "npm", Direct: false,
// 					},
// 				},
// 			},
// 		},
// 		{
// 			name: "multiple trees",
// 			compTrees: &xrayCmdUtils.BinaryGraphNode{
// 				Id: "root",
// 				Nodes: []*xrayCmdUtils.BinaryGraphNode{
// 					{
// 						Id:    "npm://A:1.0.1",
// 						Nodes: []*xrayCmdUtils.BinaryGraphNode{{Id: "go://B:1.0.0"}},
// 					},
// 					{
// 						Id: "npm://C:1.0.1",
// 					},
// 					{
// 						Id:    "npm://A:2.0.1",
// 						Nodes: []*xrayCmdUtils.BinaryGraphNode{{Id: "npm://B:1.0.0"}, {Id: "npm://C:1.0.1"}},
// 					},
// 				},
// 			},
// 			expectedSbom: Sbom{
// 				Components: []SbomEntry{
// 					{
// 						Name: "A", Version: "1.0.1", Type: "npm", Direct: true,
// 					},
// 					{
// 						Name: "A", Version: "2.0.1", Type: "npm", Direct: true,
// 					},
// 					{
// 						Name: "C", Version: "1.0.1", Type: "npm", Direct: true,
// 					},
// 					{
// 						Name: "B", Version: "1.0.0", Type: "Go", Direct: false,
// 					},
// 					{
// 						Name: "B", Version: "1.0.0", Type: "npm", Direct: false,
// 					},
// 				},
// 			},
// 		},
// 	}

// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 			sbom := CompTreeToSbom(test.compTrees)
// 			SortSbom(sbom.Components)
// 			assert.Equal(t, test.expectedSbom, sbom)
// 		})
// 	}
// }

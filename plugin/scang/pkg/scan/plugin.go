package scan

import (
	"encoding/json"
	"fmt"
	"net/rpc"
	"os"
	"os/exec"
	"reflect"

	cdx "github.com/CycloneDX/cyclonedx-go"
	goplugin "github.com/hashicorp/go-plugin"
)

const PluginName = "scang"

var PluginHandshakeConfig = goplugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "SCANG_PLUGIN_MAGIC_COOKIE",
	MagicCookieValue: "scang-plugin-v1",
}

// Plugin Implementation that talks over rpc
type ScannerRPCScanRequest struct {
	Path       string
	ConfigJSON string
}

type ScannerRPCScanResponse struct {
	BOM   *cdx.BOM
	Error error
}

type ScannerRPCClient struct {
	client *rpc.Client
}

func (g *ScannerRPCClient) Scan(path string, config Config) (*cdx.BOM, error) {
	configJSONBytes, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}

	args := ScannerRPCScanRequest{
		Path:       path,
		ConfigJSON: string(configJSONBytes),
	}

	resp := ScannerRPCScanResponse{}
	rpcErr := g.client.Call("Plugin.Scan", args, &resp)
	if rpcErr != nil {
		return nil, rpcErr
	}
	return resp.BOM, resp.Error
}

// RPC Server that ScanPluginRPC talks to
type ScannerRPCServer struct {
	Impl Scanner
}

func (s *ScannerRPCServer) Scan(args ScannerRPCScanRequest, resp *ScannerRPCScanResponse) error {
	var cfg Config
	if err := json.Unmarshal([]byte(args.ConfigJSON), &cfg); err != nil {
		*resp = ScannerRPCScanResponse{BOM: nil, Error: err}
		return err
	}

	bom, scanErr := s.Impl.Scan(args.Path, cfg)
	*resp = ScannerRPCScanResponse{BOM: bom, Error: scanErr}
	return nil
}

// Implementation of plugin
type Plugin struct {
	goplugin.NetRPCUnsupportedPlugin
	Impl Scanner
}

func (p *Plugin) Server(broker *goplugin.MuxBroker) (interface{}, error) {
	return &ScannerRPCServer{Impl: p.Impl}, nil
}

func (p *Plugin) Client(broker *goplugin.MuxBroker, client *rpc.Client) (interface{}, error) {
	return &ScannerRPCClient{client: client}, nil
}

func CreateScannerPluginClient(path string) (Scanner, error) {
	_, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	client := goplugin.NewClient(&goplugin.ClientConfig{
		HandshakeConfig: PluginHandshakeConfig,
		Plugins:         map[string]goplugin.Plugin{PluginName: &Plugin{}},
		Cmd:             &exec.Cmd{Path: path},
		Managed:         true,
	})

	defer func() {
		if err != nil {
			client.Kill()
		}
	}()

	rpcClient, err := client.Client()
	if err != nil {
		return nil, err
	}

	raw, err := rpcClient.Dispense(PluginName)
	if err != nil {
		return nil, err
	}

	scanPlugin, ok := raw.(Scanner)
	if !ok {
		return nil, fmt.Errorf("plugin is not of type scangplugin.ScangPlugin")
	}

	return scanPlugin, nil
}

func init() {
	//These are hints so that the garbler won't garble these symbols
	_ = reflect.TypeOf(ScannerRPCScanRequest{})
	_ = reflect.TypeOf(ScannerRPCScanResponse{})
}

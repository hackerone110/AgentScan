package mcpwire

import (
	"encoding/json"
	"testing"
)

func TestDiscoverRequestShape(t *testing.T) {
	var m map[string]interface{}
	if err := json.Unmarshal(DiscoverRequest(), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["method"] != "server/discover" {
		t.Fatalf("method = %v, want server/discover", m["method"])
	}
	params, _ := m["params"].(map[string]interface{})
	meta, _ := params["_meta"].(map[string]interface{})
	if meta["io.modelcontextprotocol/protocolVersion"] != ModernProtocolVersion {
		t.Fatalf("_meta protocolVersion = %v, want %s", meta["io.modelcontextprotocol/protocolVersion"], ModernProtocolVersion)
	}
	if _, ok := meta["io.modelcontextprotocol/clientInfo"]; !ok {
		t.Fatalf("_meta missing clientInfo: %v", meta)
	}
	if _, ok := meta["io.modelcontextprotocol/clientCapabilities"]; !ok {
		t.Fatalf("_meta missing clientCapabilities: %v", meta)
	}
}

func TestModernRequestMergesExtraParams(t *testing.T) {
	body := ModernRequest("call-1", "tools/call", map[string]interface{}{"name": "get_weather"})
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	params, _ := m["params"].(map[string]interface{})
	if params["name"] != "get_weather" {
		t.Fatalf("params.name = %v, want get_weather", params["name"])
	}
	if _, ok := params["_meta"].(map[string]interface{}); !ok {
		t.Fatalf("params missing _meta: %v", params)
	}
}

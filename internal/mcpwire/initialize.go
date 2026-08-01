package mcpwire

import "encoding/json"

// ModernProtocolVersion 是 2026-07-28 修订的协议版本字符串。
const ModernProtocolVersion = "2026-07-28"

var (
	initBodyStreamable = mustBuildInitializeRequest("2025-06-18")
	initBodyLegacy     = mustBuildInitializeRequest("2024-11-05")
	initBodyInvalid    = mustBuildInitializeRequest("9999-99-99")

	discoverBodyModern = mustBuildModernRequest("discover-1", "server/discover", nil)
)

// modernMeta 构造 2026-07-28 无状态请求的 params._meta。
// 版本/身份/能力不再走 initialize 握手，而是每个请求随 _meta 携带。
func modernMeta(version string) map[string]interface{} {
	return map[string]interface{}{
		"io.modelcontextprotocol/protocolVersion": version,
		"io.modelcontextprotocol/clientInfo": map[string]interface{}{
			"name":    "mcp-client",
			"version": "1.0.0",
		},
		"io.modelcontextprotocol/clientCapabilities": map[string]interface{}{},
	}
}

// mustBuildModernRequest 构造一个 2026-07-28 modern JSON-RPC 请求体。
// extraParams 会与 _meta 合并进 params（如 tools/list 的空参数、tools/call 的 name/arguments）。
func mustBuildModernRequest(id, method string, extraParams map[string]interface{}) []byte {
	params := map[string]interface{}{
		"_meta": modernMeta(ModernProtocolVersion),
	}
	for k, v := range extraParams {
		params[k] = v
	}
	b, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params":  params,
	})
	return b
}

// DiscoverRequest 返回 2026-07-28 的 server/discover 探活请求体。
// 这是 modern 服务器唯一 MUST 实现的 RPC，用于探活并获取
// supportedVersions / capabilities / serverInfo。
func DiscoverRequest() []byte {
	return discoverBodyModern
}

// ModernRequest 构造任意 modern JSON-RPC 请求体（tools/list、prompts/list 等）。
// id 用字符串以匹配无状态请求的惯例；extraParams 可为 nil。
func ModernRequest(id, method string, extraParams map[string]interface{}) []byte {
	return mustBuildModernRequest(id, method, extraParams)
}

func mustBuildInitializeRequest(version string) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": version,
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]interface{}{
				"name":    "mcp-client",
				"version": "1.0.0",
			},
		},
	})
	return b
}

// InitializeRequest returns a pre-built MCP initialize request body when possible.
func InitializeRequest(version string) []byte {
	switch version {
	case "2025-06-18":
		return initBodyStreamable
	case "2024-11-05":
		return initBodyLegacy
	case "9999-99-99":
		return initBodyInvalid
	default:
		return mustBuildInitializeRequest(version)
	}
}

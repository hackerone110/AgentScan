package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agentscan/agentscan/internal/mcpwire"
	"github.com/agentscan/agentscan/pkg/models"
)

// discoverResultBody 是 2026-07-28 server/discover 的合法 DiscoverResult 响应。
const discoverResultBody = `{"jsonrpc":"2.0","id":"discover-1","result":{` +
	`"resultType":"complete",` +
	`"supportedVersions":["2026-07-28"],` +
	`"capabilities":{"tools":{},"resources":{}},` +
	`"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"ExampleServer","version":"1.0.0"}},` +
	`"instructions":"weather utilities","ttlMs":3600000,"cacheScope":"public"}}`

func TestScoreFingerprintParsesDiscoverResult(t *testing.T) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(discoverResultBody), &data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	score, name, ver, protoVer, caps, ev := scoreFingerprintDetailed(data)
	if score < 0.35 {
		t.Fatalf("score = %v, want >= 0.35; signals=%v", score, ev.Signals)
	}
	if name != "ExampleServer" || ver != "1.0.0" {
		t.Fatalf("serverInfo = %q/%q, want ExampleServer/1.0.0", name, ver)
	}
	if protoVer != "2026-07-28" {
		t.Fatalf("protocolVersion = %q, want 2026-07-28 (from supportedVersions)", protoVer)
	}
	if _, ok := caps["tools"]; !ok {
		t.Fatalf("capabilities missing tools: %v", caps)
	}
	if !hasSignal(ev.Signals, "modern_result_type") || !hasSignal(ev.Signals, "meta_server_info") {
		t.Fatalf("expected modern signals, got %v", ev.Signals)
	}
}

func TestTryStreamableHTTPModernDetectsDiscoverResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/mcp" {
			http.NotFound(w, r)
			return
		}
		// 校验必需头（modern 服务器会做，测试也确认我们发对了）
		if r.Header.Get("Mcp-Method") != "server/discover" ||
			r.Header.Get("MCP-Protocol-Version") != mcpwire.ModernProtocolVersion {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"x","error":{"code":-32020,"message":"header mismatch"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(discoverResultBody))
	}))
	defer server.Close()

	client := buildHTTPClient("", 2000000000)
	got := tryStreamableHTTPModern(context.Background(), client, server.URL+"/mcp", "/mcp", 2000000000, nil)
	if got == nil {
		t.Fatal("tryStreamableHTTPModern() = nil, want modern MCP result")
	}
	if got.Transport != models.TransportStreamableHTTPModern {
		t.Fatalf("Transport = %q, want streamable_http_modern", got.Transport)
	}
	if got.ServerName != "ExampleServer" {
		t.Fatalf("ServerName = %q, want ExampleServer", got.ServerName)
	}
	if !got.NoAuth || got.AuthRequired {
		t.Fatalf("expected no-auth result, got NoAuth=%v AuthRequired=%v", got.NoAuth, got.AuthRequired)
	}
}

func TestTryStreamableHTTPModernDetectsUnsupportedVersionError(t *testing.T) {
	// 服务器只支持别的版本，返回 -32022：仍是存活的 modern MCP（无认证）。
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"discover-1","error":{"code":-32022,` +
			`"message":"Unsupported protocol version","data":{"supported":["2099-01-01"],"requested":"2026-07-28"}}}`))
	}))
	defer server.Close()

	client := buildHTTPClient("", 2000000000)
	got := tryStreamableHTTPModern(context.Background(), client, server.URL+"/mcp", "/mcp", 2000000000, nil)
	if got == nil {
		t.Fatal("tryStreamableHTTPModern() = nil, want live modern MCP via -32022")
	}
	if got.AuthRequired {
		t.Fatalf("AuthRequired = true, want false for version error")
	}
	if !strings.Contains(got.Evidence.JSONRPC.ErrorCode, "-32022") {
		t.Fatalf("ErrorCode = %q, want -32022", got.Evidence.JSONRPC.ErrorCode)
	}
}

func TestMCPAuthRequiredAcceptsModernErrorCodeUnder401(t *testing.T) {
	// modern 服务器不发 Mcp-Session-Id；用 401 + JSON-RPC -32022 顶替该信号。
	resp := httptest.NewRecorder()
	resp.Header().Set("Content-Type", "application/json")
	resp.WriteHeader(http.StatusUnauthorized)
	_, _ = resp.WriteString(`{"jsonrpc":"2.0","error":{"code":-32022,"message":"unsupported"}}`)

	got, ev := isMCPAuthRequiredWithEvidence(resp.Result(), "/mcp", nil)
	if !got {
		t.Fatalf("auth-required = false, want true; evidence=%#v", ev)
	}
}

func TestBodyModernErrorCode(t *testing.T) {
	cases := map[string]string{
		`{"error":{"code":-32020}}`:  "-32020",
		`{"error":{"code": -32022}}`: "-32022",
		`{"error":{"code":-32021}}`:  "-32021",
		`{"error":{"code":-32601}}`:  "", // JSON-RPC 标准 Method not found，非 MCP 专属，不匹配
		`{"error":{"code":-32001}}`:  "", // 实现自定义区间，非 modern 保留码
		`{"error":{"code":-320201}}`: "", // 不能被 -32020 前缀误配
		`{"result":{"tools":[]}}`:    "", // 无 error
	}
	for body, want := range cases {
		if got := bodyModernErrorCode(body); got != want {
			t.Fatalf("bodyModernErrorCode(%q) = %q, want %q", body, got, want)
		}
	}
}

// 回归：普通 JSON-RPC 服务器对 server/discover 返回 404/-32601（Method not found）
// 不能被误判为 modern MCP（-32601 是 JSON-RPC 标准码，非 MCP 专属）。
func TestTryStreamableHTTPModernIgnoresGenericMethodNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"}}`))
	}))
	defer server.Close()

	client := buildHTTPClient("", 2000000000)
	got := tryStreamableHTTPModern(context.Background(), client, server.URL+"/mcp", "/mcp", 2000000000, nil)
	if got != nil {
		t.Fatalf("tryStreamableHTTPModern() = %#v, want nil for generic -32601", got)
	}
}

// 回归：带 result.resultType + result.supportedVersions 的非 MCP JSON（值不合 MCP 格式）
// 不能凑够 0.35 阈值。
func TestScoreFingerprintRejectsGenericResultTypeVersions(t *testing.T) {
	var data map[string]interface{}
	_ = json.Unmarshal([]byte(`{"result":{"resultType":"success","supportedVersions":["v1"]}}`), &data)
	score, _, _, _, _, ev := scoreFingerprintDetailed(data)
	if score >= 0.35 {
		t.Fatalf("score = %v, want < 0.35 for generic result; signals=%v", score, ev.Signals)
	}
}

// 回归（缺陷 C）：严格 modern 服务器对空 clientCapabilities 探测回 HTTP 200 + -32021，
// 应识别为存活的 no-auth modern MCP，而不是被 0.35 门槛丢弃。
func TestTryStreamableHTTPModernDetects200ErrorBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"discover-1","error":{"code":-32021,"message":"missing required client capability"}}`))
	}))
	defer server.Close()

	client := buildHTTPClient("", 2000000000)
	got := tryStreamableHTTPModern(context.Background(), client, server.URL+"/mcp", "/mcp", 2000000000, nil)
	if got == nil {
		t.Fatal("tryStreamableHTTPModern() = nil, want live modern MCP via 200 + -32021")
	}
	if got.AuthRequired || !got.NoAuth {
		t.Fatalf("expected no-auth, got AuthRequired=%v NoAuth=%v", got.AuthRequired, got.NoAuth)
	}
	if got.Evidence.JSONRPC.ErrorCode != "-32021" {
		t.Fatalf("ErrorCode = %q, want -32021", got.Evidence.JSONRPC.ErrorCode)
	}
}

// 回归（缺陷 D）：裸 401 无任何 MCP 佐证的非 MCP 站点（basic-auth/WAF），不能被报成 modern MCP。
func TestTryStreamableHTTPModernIgnoresBare401(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="site"`)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("login required"))
	}))
	defer server.Close()

	client := buildHTTPClient("", 2000000000)
	got := tryStreamableHTTPModern(context.Background(), client, server.URL+"/mcp", "/mcp", 2000000000, nil)
	if got != nil {
		t.Fatalf("tryStreamableHTTPModern() = %#v, want nil for bare 401", got)
	}
}

// 回归（缺陷 D）：401 + MCP 保留错误码 -32022 是有佐证的认证挑战，应报 auth-required。
func TestTryStreamableHTTPModernDetects401WithModernCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32022,"message":"unsupported version"}}`))
	}))
	defer server.Close()

	client := buildHTTPClient("", 2000000000)
	got := tryStreamableHTTPModern(context.Background(), client, server.URL+"/mcp", "/mcp", 2000000000, nil)
	if got == nil || !got.AuthRequired {
		t.Fatalf("want auth-required modern MCP, got %#v", got)
	}
}

func hasSignal(signals []string, want string) bool {
	for _, s := range signals {
		if s == want {
			return true
		}
	}
	return false
}

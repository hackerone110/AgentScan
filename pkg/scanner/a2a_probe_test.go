package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agentscan/agentscan/pkg/models"
)

func TestProbeA2ALegacyAgentJSONNoAuthJSONRPC(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/agent.json":
			writeJSON(t, w, map[string]interface{}{
				"name":        "system-admin-agent",
				"description": "System administration agent",
				"url":         "/a2a",
				"capabilities": map[string]interface{}{
					"streaming":         false,
					"pushNotifications": false,
				},
				"skills": []map[string]interface{}{
					{"id": "schedule_system_commands", "name": "schedule_system_commands", "description": "Schedule system commands"},
				},
			})
		case "/a2a":
			w.WriteHeader(http.StatusNotFound)
			writeJSON(t, w, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      1,
				"error": map[string]interface{}{
					"code":    -32601,
					"message": "Method not found",
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	got := ProbeA2AWithHostname(context.Background(), srv.URL, "", "", 1000, nil)
	if got == nil {
		t.Fatal("ProbeA2AWithHostname() returned nil")
	}
	if got.Profile != models.A2AProfileLegacyAgentJSON {
		t.Fatalf("profile = %q, want %q", got.Profile, models.A2AProfileLegacyAgentJSON)
	}
	if got.ExposureStatus != models.A2AExposureJSONRPCNoAuth {
		t.Fatalf("exposure status = %q, want %q", got.ExposureStatus, models.A2AExposureJSONRPCNoAuth)
	}
	if !got.NoAuth {
		t.Fatal("NoAuth = false, want true")
	}
	if len(got.Interfaces) != 1 || got.Interfaces[0].Status != models.A2AStatusNoAuthJSONRPCReachable {
		t.Fatalf("interfaces = %#v, want no-auth JSON-RPC reachable", got.Interfaces)
	}
	if !containsA2ATestString(got.ExposureSignals, "system_admin_skill_names") {
		t.Fatalf("signals = %#v, want system_admin_skill_names", got.ExposureSignals)
	}
}

func TestProbeA2AEndpointDisabledIsSeparateStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/agent.json":
			writeJSON(t, w, map[string]interface{}{
				"name":        "OmniRoute AI Gateway",
				"description": "Routing gateway",
				"url":         "http://localhost:20128/a2a",
				"capabilities": map[string]interface{}{
					"streaming":         true,
					"pushNotifications": false,
				},
				"skills": []map[string]interface{}{
					{"id": "smart-routing", "name": "Smart Request Routing"},
				},
			})
		case "/a2a":
			w.WriteHeader(http.StatusServiceUnavailable)
			writeJSON(t, w, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      1,
				"error": map[string]interface{}{
					"code":    -32000,
					"message": "A2A endpoint is disabled. Enable it from the Endpoints page.",
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	got := ProbeA2AWithHostname(context.Background(), srv.URL, "", "", 1000, nil)
	if got == nil {
		t.Fatal("ProbeA2AWithHostname() returned nil")
	}
	if got.ExposureStatus != models.A2AExposureDisabled {
		t.Fatalf("exposure status = %q, want %q", got.ExposureStatus, models.A2AExposureDisabled)
	}
	if got.NoAuth {
		t.Fatal("NoAuth = true, want false for disabled endpoint")
	}
	if !got.EndpointDisabled {
		t.Fatal("EndpointDisabled = false, want true")
	}
	if len(got.Interfaces) != 1 || !got.Interfaces[0].PrivateHostAdvertised {
		t.Fatalf("interfaces = %#v, want private host advertised and rebased", got.Interfaces)
	}
}

// 召回优先：alternate-schema（Agent Protocol 等）不再直接丢弃，而是降级保留并标注
// non_a2a_agent_discovery，永不 confirmed。
func TestProbeA2AAlternateSchemaDowngradedNotDropped(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/agent.json" {
			http.NotFound(w, r)
			return
		}
		writeJSON(t, w, map[string]interface{}{
			"$schema":     "https://agentprotocol.ai/schema/agent.json",
			"name":        "Not A2A",
			"description": "Agent Protocol document",
			"capabilities": map[string]interface{}{
				"actions": []interface{}{},
			},
		})
	})

	// 应保留为 non_a2a_agent_discovery，永不 confirmed
	srv := httptest.NewServer(handler)
	defer srv.Close()
	got := ProbeA2AWithHostname(context.Background(), srv.URL, "", "", 1000, nil)
	if got == nil {
		t.Fatal("ProbeA2AWithHostname() = nil, want non_a2a_agent_discovery result")
	}
	if got.A2AConfirmed {
		t.Fatal("A2AConfirmed = true, want false for alternate schema")
	}
	if got.ExposureStatus != models.A2AExposureNonA2ADiscovery {
		t.Fatalf("exposure status = %q, want %q", got.ExposureStatus, models.A2AExposureNonA2ADiscovery)
	}
	if !containsA2ATestString(got.ExposureSignals, "non_a2a_agent_discovery") {
		t.Fatalf("signals = %#v, want non_a2a_agent_discovery", got.ExposureSignals)
	}
	if !containsA2ATestString(got.Negatives, "agent_protocol_like") {
		t.Fatalf("negatives = %#v, want agent_protocol_like", got.Negatives)
	}
}

// 召回优先：ACP 特征（agentId + runs）被标注为 acp_like 并降级为 non_a2a_agent_discovery。
func TestProbeA2AACPSchemaFlaggedNonA2A(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/agent.json" {
			http.NotFound(w, r)
			return
		}
		writeJSON(t, w, map[string]interface{}{
			"agentId":     "acp-agent-1",
			"name":        "ACP Agent",
			"description": "Agent Communication Protocol agent",
			"runs":        map[string]interface{}{"endpoint": "/runs"},
			"capabilities": map[string]interface{}{
				"streaming": false,
			},
			"skills": []map[string]interface{}{
				{"id": "x", "name": "x"},
			},
		})
	}))
	defer srv.Close()

	got := ProbeA2AWithHostname(context.Background(), srv.URL, "", "", 1000, nil)
	if got == nil {
		t.Fatal("ProbeA2AWithHostname() returned nil, want non_a2a result for ACP card")
	}
	if got.A2AConfirmed {
		t.Fatal("A2AConfirmed = true, want false for ACP card")
	}
	if got.ExposureStatus != models.A2AExposureNonA2ADiscovery {
		t.Fatalf("exposure status = %q, want %q", got.ExposureStatus, models.A2AExposureNonA2ADiscovery)
	}
	if !containsA2ATestString(got.Negatives, "acp_like") {
		t.Fatalf("negatives = %#v, want acp_like", got.Negatives)
	}
}

// 召回优先：非标准路径 + 强 A2A 信号（supportedInterfaces）也能 confirmed，
// 覆盖多租户/子路径 mount 及自定义 card 路径部署。
func TestProbeA2ANonstandardPathConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/custom/mycard.json":
			writeJSON(t, w, map[string]interface{}{
				"name":            "Custom Path Agent",
				"description":     "Agent served at a nonstandard card path",
				"protocolVersion": "1.0",
				"capabilities":    map[string]interface{}{"streaming": true},
				"skills":          []map[string]interface{}{{"id": "s", "name": "s"}},
				"supportedInterfaces": []map[string]interface{}{
					{"protocolBinding": "JSONRPC", "url": "/a2a"},
				},
			})
		case "/a2a":
			writeJSON(t, w, map[string]interface{}{
				"jsonrpc": "2.0", "id": 1,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// 用户直接提供非标准 card 路径（以 .json 结尾 → buildA2ACardPaths 直接探测）
	got := ProbeA2AWithHostname(context.Background(), srv.URL, "", "/custom/mycard.json", 1000, nil)
	if got == nil {
		t.Fatal("ProbeA2AWithHostname() returned nil, want confirmed for nonstandard path")
	}
	if !got.A2AConfirmed {
		t.Fatalf("A2AConfirmed = false, want true. status=%q score=%.2f path=%q", got.ExposureStatus, got.FingerprintScore, got.CardPath)
	}
	if !containsA2ATestString(got.Signals, "nonstandard_card_path") {
		t.Fatalf("signals = %#v, want nonstandard_card_path", got.Signals)
	}
}

// 召回优先：HTTP+JSON binding 也被主动探测（read-only unknown-method）。
func TestProbeA2AHTTPJSONBindingProbed(t *testing.T) {
	probed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/agent-card.json":
			writeJSON(t, w, map[string]interface{}{
				"name":            "REST Agent",
				"description":     "HTTP+JSON binding agent",
				"protocolVersion": "1.0",
				"capabilities":    map[string]interface{}{"streaming": false},
				"skills":          []map[string]interface{}{{"id": "s", "name": "s"}},
				"supportedInterfaces": []map[string]interface{}{
					{"protocolBinding": "HTTP+JSON", "url": "/rpc"},
				},
			})
		case "/rpc":
			probed = true
			writeJSON(t, w, map[string]interface{}{
				"jsonrpc": "2.0", "id": 1,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	got := ProbeA2AWithHostname(context.Background(), srv.URL, "", "", 1000, nil)
	if got == nil {
		t.Fatal("ProbeA2AWithHostname() returned nil")
	}
	if !probed {
		t.Fatal("HTTP+JSON interface was not actively probed, want probed")
	}
	if got.ExposureStatus != models.A2AExposureJSONRPCNoAuth {
		t.Fatalf("exposure status = %q, want %q", got.ExposureStatus, models.A2AExposureJSONRPCNoAuth)
	}
}

func TestProbeA2AExtendedCardNoAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/agent-card.json":
			writeJSON(t, w, map[string]interface{}{
				"name":            "Docs by LangChain",
				"description":     "Documentation agent",
				"protocolVersion": "1.0",
				"capabilities": map[string]interface{}{
					"streaming":         false,
					"extendedAgentCard": true,
				},
				"skills": []map[string]interface{}{
					{"id": "doc-search", "name": "Document Search"},
				},
				"supportedInterfaces": []map[string]interface{}{
					{"protocolBinding": "JSONRPC", "url": "/a2a"},
				},
			})
		case "/a2a":
			// GetExtendedAgentCard returns result without auth → extended_card_no_auth
			// AgentScanProbe → method not found
			var req map[string]interface{}
			json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
			method, _ := req["method"].(string)
			if method == "GetExtendedAgentCard" {
				writeJSON(t, w, map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      req["id"],
					"result": map[string]interface{}{
						"name":   "Extended LangChain Card",
						"skills": []interface{}{},
					},
				})
				return
			}
			writeJSON(t, w, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req["id"],
				"error": map[string]interface{}{
					"code":    -32601,
					"message": "Method not found",
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	got := ProbeA2AWithHostname(context.Background(), srv.URL, "", "", 1000, nil)
	if got == nil {
		t.Fatal("ProbeA2AWithHostname() returned nil")
	}
	if got.Profile != models.A2AProfileAgentCard {
		t.Fatalf("profile = %q, want %q", got.Profile, models.A2AProfileAgentCard)
	}
	if !containsA2ATestString(got.ExposureSignals, "extended_card_no_auth") {
		t.Fatalf("ExposureSignals = %v, want extended_card_no_auth", got.ExposureSignals)
	}
}

func TestProbeA2ADeclaredAuthDetection(t *testing.T) {
	tests := []struct {
		name         string
		card         map[string]interface{}
		wantDeclared string
	}{
		{
			name: "no_security_fields",
			card: map[string]interface{}{
				"name":         "Open Agent",
				"description":  "No auth",
				"url":          "/a2a",
				"capabilities": map[string]interface{}{"streaming": false},
				"skills":       []interface{}{map[string]interface{}{"id": "x", "name": "x"}},
			},
			wantDeclared: "declared_none",
		},
		{
			name: "security_array_present",
			card: map[string]interface{}{
				"name":         "Secure Agent",
				"description":  "Requires auth",
				"url":          "/a2a",
				"capabilities": map[string]interface{}{"streaming": false},
				"skills":       []interface{}{map[string]interface{}{"id": "x", "name": "x"}},
				"securitySchemes": map[string]interface{}{
					"bearer": map[string]interface{}{"type": "http", "scheme": "bearer"},
				},
				"security": []interface{}{
					map[string]interface{}{"bearer": []interface{}{}},
				},
			},
			wantDeclared: "declared_required",
		},
		{
			name: "schemes_only_no_requirements",
			card: map[string]interface{}{
				"name":         "Ambiguous Agent",
				"description":  "Has schemes but no requirements",
				"url":          "/a2a",
				"capabilities": map[string]interface{}{"streaming": false},
				"skills":       []interface{}{map[string]interface{}{"id": "x", "name": "x"}},
				"securitySchemes": map[string]interface{}{
					"bearer": map[string]interface{}{"type": "http"},
				},
			},
			wantDeclared: "declared_ambiguous",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/.well-known/agent.json" {
					writeJSON(t, w, tt.card)
					return
				}
				// /a2a → method not found
				writeJSON(t, w, map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      1,
					"error":   map[string]interface{}{"code": -32601, "message": "Method not found"},
				})
			}))
			defer srv.Close()

			got := ProbeA2AWithHostname(context.Background(), srv.URL, "", "", 1000, nil)
			if got == nil {
				t.Fatal("ProbeA2AWithHostname() returned nil")
			}
			if got.Evidence.Auth.Declared != tt.wantDeclared {
				t.Fatalf("declared auth = %q, want %q", got.Evidence.Auth.Declared, tt.wantDeclared)
			}
		})
	}
}

func TestHasSystemAdminSkillAvoidsSingleGenericWords(t *testing.T) {
	skills := []models.A2ASkill{
		{ID: "calendar", Name: "Calendar Updates", Description: "Update my calendar from voice commands"},
		{ID: "order-status", Name: "Order Status", Description: "Update order status for customers"},
	}
	if hasSystemAdminSkill(skills) {
		t.Fatalf("hasSystemAdminSkill() = true, want false for generic update/command skills")
	}
}

func TestHasSystemAdminSkillDetectsAdminCommandCombinations(t *testing.T) {
	skills := []models.A2ASkill{
		{ID: "ops", Name: "System Maintenance", Description: "Run package updates and service backups"},
	}
	if !hasSystemAdminSkill(skills) {
		t.Fatalf("hasSystemAdminSkill() = false, want true for system maintenance actions")
	}
}

// 提取 skill.examples 与 card.signatures（JWS）：仅记录客观字段，不做验证。
func TestProbeA2AExtractsExamplesAndSignatures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/agent-card.json":
			writeJSON(t, w, map[string]interface{}{
				"name":            "Signed Agent",
				"description":     "Agent with signed card and skill examples",
				"protocolVersion": "1.0",
				"capabilities":    map[string]interface{}{"streaming": true},
				"supportedInterfaces": []map[string]interface{}{
					{"protocolBinding": "JSONRPC", "url": "/a2a"},
				},
				"skills": []map[string]interface{}{
					{
						"id":       "search",
						"name":     "Search",
						"examples": []interface{}{"find invoices from Q3", "search all tickets"},
					},
				},
				"signatures": []interface{}{
					map[string]interface{}{"protected": "eyJhbGciOiJFUzI1NiJ9", "signature": "abc"},
				},
			})
		case "/a2a":
			writeJSON(t, w, map[string]interface{}{
				"jsonrpc": "2.0", "id": 1,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	got := ProbeA2AWithHostname(context.Background(), srv.URL, "", "", 1000, nil)
	if got == nil {
		t.Fatal("ProbeA2AWithHostname() returned nil")
	}
	if len(got.Skills) != 1 || len(got.Skills[0].Examples) != 2 {
		t.Fatalf("skill examples = %#v, want 2 examples extracted", got.Skills)
	}
	if got.Skills[0].Examples[0] != "find invoices from Q3" {
		t.Fatalf("skill example[0] = %q, want %q", got.Skills[0].Examples[0], "find invoices from Q3")
	}
	if !got.HasSignatures {
		t.Fatal("HasSignatures = false, want true for card with signatures")
	}
	if !containsA2ATestString(got.ExposureSignals, "has_jws_signature") {
		t.Fatalf("signals = %#v, want has_jws_signature", got.ExposureSignals)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, v interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatalf("json encode: %v", err)
	}
}

func containsA2ATestString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

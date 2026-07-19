package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/agentscan/agentscan/pkg/models"
)

type A2AJSONReport struct {
	Version  string              `json:"version"`
	Summary  A2AJSONSummary      `json:"summary"`
	Clusters []A2ACluster        `json:"clusters,omitempty"`
	Results  []*models.A2AServer `json:"results"`
}

type A2AJSONSummary struct {
	Total                    int `json:"total"`
	Confirmed                int `json:"confirmed"`
	PublicCards              int `json:"public_cards"`
	NoAuthJSONRPC            int `json:"no_auth_jsonrpc"`
	AuthRequired             int `json:"auth_required"`
	EndpointDisabled         int `json:"endpoint_disabled"`
	PrivateHostAdvertised    int `json:"private_host_advertised"`
	ProbableAgentDiscoveries int `json:"probable_agent_discoveries"`
	NonA2ADiscoveries        int `json:"non_a2a_discoveries"`
	TotalSkills              int `json:"total_skills"`
}

func WriteA2AJSON(results []*models.A2AServer, path string) error {
	report := A2AJSONReport{
		Version:  "1.0",
		Summary:  summarizeA2AResults(results),
		Clusters: multiDeploymentClusters(results),
		Results:  results,
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}
	if path == "" || path == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func PrintA2AServer(s *models.A2AServer, noColor bool) {
	FprintA2AServer(os.Stdout, s, noColor)
}

func FprintA2AServer(w io.Writer, s *models.A2AServer, noColor bool) {
	bold, reset, statusColor := "", "", ""
	if !noColor {
		bold = colorBold
		reset = colorReset
		switch s.ExposureStatus {
		case models.A2AExposureJSONRPCNoAuth:
			statusColor = colorGreen + colorBold
		case models.A2AExposureAuthRequired, models.A2AExposureDisabled:
			statusColor = colorYellow + colorBold
		case models.A2AExposureProbable, models.A2AExposureNonA2ADiscovery:
			// 召回优先噪声：弱化，让高置信结果更醒目
			statusColor = colorDim
		}
	}

	target := fmt.Sprintf("%s:%d%s", s.IP, s.Port, s.CardPath)
	fmt.Fprintf(w, "%s[A2A]%s %-30s %-29s %s%s%s\n",
		bold, reset,
		target,
		string(s.Profile),
		statusColor, s.ExposureStatus, reset,
	)

	if s.AgentName != "" {
		fmt.Fprintf(w, "      agent    %s\n", s.AgentName)
	}
	fmt.Fprintf(w, "      exposed  skills=%d  interfaces=%d  score=%.2f\n",
		s.SkillCount, len(s.Interfaces), s.FingerprintScore)
	if len(s.ExposureSignals) > 0 {
		fmt.Fprintf(w, "      signals  %s\n", strings.Join(s.ExposureSignals, ", "))
	}
	for _, iface := range s.Interfaces {
		status := iface.Status
		if status == "" {
			status = models.A2AStatusUnknown
		}
		fmt.Fprintf(w, "      iface    %-34s %-30s %s\n", status, iface.Binding, iface.URL)
		if iface.PrivateHostAdvertised && iface.AdvertisedURL != "" {
			fmt.Fprintf(w, "               advertised=%s\n", iface.AdvertisedURL)
		}
	}
	fmt.Fprintln(w)
}

func PrintA2ASummary(results []*models.A2AServer, noColor bool) {
	bold, reset, redBold, yellow := "", "", "", ""
	if !noColor {
		bold = colorBold
		reset = colorReset
		redBold = "\033[31m\033[1m"
		yellow = "\033[33m\033[1m"
	}
	summary := summarizeA2AResults(results)

	// no-auth-jsonrpc — red bold if > 0
	noAuthStr := fmt.Sprintf("no-auth-jsonrpc=%d", summary.NoAuthJSONRPC)
	if summary.NoAuthJSONRPC > 0 {
		noAuthStr = fmt.Sprintf("%sno-auth-jsonrpc=%d%s", redBold, summary.NoAuthJSONRPC, reset)
	}

	// disabled — yellow if > 0
	disabledStr := fmt.Sprintf("disabled=%d", summary.EndpointDisabled)
	if summary.EndpointDisabled > 0 {
		disabledStr = fmt.Sprintf("%sdisabled=%d%s", yellow, summary.EndpointDisabled, reset)
	}

	fmt.Printf("%sSummary%s  A2A=%d  confirmed=%d  public-cards=%d  %s\n",
		bold, reset, summary.Total, summary.Confirmed, summary.PublicCards, noAuthStr)
	fmt.Printf("         auth-required=%d  %s  private-host=%d  probable=%d  non-a2a=%d  skills=%d\n",
		summary.AuthRequired, disabledStr, summary.PrivateHostAdvertised, summary.ProbableAgentDiscoveries, summary.NonA2ADiscoveries, summary.TotalSkills)

	printA2AClusters(results, bold, reset, redBold)
}

// printA2AClusters 在 summary 后打印 Top 产品家族（部署数 >= 2），避免同款 card 刷屏。
// 最多展示 5 个家族。
func printA2AClusters(results []*models.A2AServer, bold, reset, redBold string) {
	clusters := multiDeploymentClusters(results)
	if len(clusters) == 0 {
		return
	}
	const maxShow = 5
	fmt.Printf("%sTop product families%s (deployments >= 2)\n", bold, reset)
	for i, c := range clusters {
		if i >= maxShow {
			fmt.Printf("         ... and %d more families\n", len(clusters)-maxShow)
			break
		}
		noAuth := fmt.Sprintf("no-auth=%d", c.NoAuthCount)
		if c.NoAuthCount > 0 && redBold != "" {
			noAuth = fmt.Sprintf("%sno-auth=%d%s", redBold, c.NoAuthCount, reset)
		}
		ver := ""
		if c.Version != "" {
			ver = " v" + c.Version
		}
		fmt.Printf("         %2d×  %-32s%s  %s  (e.g. %s)\n", c.Count, c.ProductName, ver, noAuth, c.SampleTarget)
	}
}

func summarizeA2AResults(results []*models.A2AServer) A2AJSONSummary {
	summary := A2AJSONSummary{Total: len(results)}
	for _, r := range results {
		if r.A2AConfirmed {
			summary.Confirmed++
		}
		if r.ExposureStatus == models.A2AExposureProbable {
			summary.ProbableAgentDiscoveries++
		}
		if r.ExposureStatus == models.A2AExposureNonA2ADiscovery {
			summary.NonA2ADiscoveries++
		}
		if r.ExposureStatus == models.A2AExposureCardPublic || r.A2AConfirmed {
			summary.PublicCards++
		}
		if r.NoAuth || r.ExposureStatus == models.A2AExposureJSONRPCNoAuth {
			summary.NoAuthJSONRPC++
		}
		if r.AuthRequired || r.ExposureStatus == models.A2AExposureAuthRequired {
			summary.AuthRequired++
		}
		if r.EndpointDisabled || r.ExposureStatus == models.A2AExposureDisabled {
			summary.EndpointDisabled++
		}
		for _, iface := range r.Interfaces {
			if iface.PrivateHostAdvertised {
				summary.PrivateHostAdvertised++
				break
			}
		}
		summary.TotalSkills += r.SkillCount
	}
	return summary
}

// A2ACluster 聚类：一个产品家族（同名+同版本+同 skill 集合）的多个部署。
// Quake 实测一次扫描可含 163 张同款 card，聚类避免终端/报告被单一产品刷屏。
type A2ACluster struct {
	Key          string `json:"key"`
	ProductName  string `json:"product_name"`
	Version      string `json:"version,omitempty"`
	Count        int    `json:"count"`
	NoAuthCount  int    `json:"no_auth_count"`
	SampleTarget string `json:"sample_target"`
}

// clusterA2AResults 按 产品名+版本+排序 skill IDs 聚类，返回按部署数降序的家族列表。
// 不修改传入 results；raw 输出仍保留全部条目。
func clusterA2AResults(results []*models.A2AServer) []A2ACluster {
	type acc struct {
		cluster A2ACluster
		order   int
	}
	groups := make(map[string]*acc)
	for i, r := range results {
		key := a2aClusterKey(r)
		g, ok := groups[key]
		if !ok {
			name := r.AgentName
			if name == "" {
				name = "(unnamed)"
			}
			g = &acc{
				cluster: A2ACluster{
					Key:          key,
					ProductName:  name,
					Version:      r.Version,
					SampleTarget: fmt.Sprintf("%s:%d%s", r.IP, r.Port, r.CardPath),
				},
				order: i,
			}
			groups[key] = g
		}
		g.cluster.Count++
		if r.NoAuth || r.ExposureStatus == models.A2AExposureJSONRPCNoAuth {
			g.cluster.NoAuthCount++
		}
	}

	clusters := make([]A2ACluster, 0, len(groups))
	for _, g := range groups {
		clusters = append(clusters, g.cluster)
	}
	// 部署数降序；同数按首次出现顺序稳定排序
	sort.SliceStable(clusters, func(i, j int) bool {
		if clusters[i].Count != clusters[j].Count {
			return clusters[i].Count > clusters[j].Count
		}
		return groups[clusters[i].Key].order < groups[clusters[j].Key].order
	})
	return clusters
}

// a2aClusterKey 生成聚类键：产品名 | 版本 | 排序去重后的 skill IDs。
func a2aClusterKey(r *models.A2AServer) string {
	ids := make([]string, 0, len(r.Skills))
	seen := make(map[string]struct{}, len(r.Skills))
	for _, s := range r.Skills {
		id := s.ID
		if id == "" {
			id = s.Name
		}
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return strings.ToLower(r.AgentName) + "|" + strings.ToLower(r.Version) + "|" + strings.Join(ids, ",")
}

// multiDeploymentClusters 只返回部署数 >= 2 的家族（单例无需聚类展示）。
func multiDeploymentClusters(results []*models.A2AServer) []A2ACluster {
	var out []A2ACluster
	for _, c := range clusterA2AResults(results) {
		if c.Count >= 2 {
			out = append(out, c)
		}
	}
	return out
}

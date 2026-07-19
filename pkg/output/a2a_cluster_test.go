package output

import (
	"testing"

	"github.com/agentscan/agentscan/pkg/models"
)

func makeA2AServer(ip string, port int, name, version string, skillIDs []string, noAuth bool) *models.A2AServer {
	skills := make([]models.A2ASkill, 0, len(skillIDs))
	for _, id := range skillIDs {
		skills = append(skills, models.A2ASkill{ID: id, Name: id})
	}
	s := &models.A2AServer{
		IP: ip, Port: port, CardPath: "/.well-known/agent.json",
		AgentName: name, Version: version, Skills: skills, SkillCount: len(skills),
		NoAuth: noAuth,
	}
	if noAuth {
		s.ExposureStatus = models.A2AExposureJSONRPCNoAuth
	}
	return s
}

func TestClusterA2AResultsGroupsDuplicates(t *testing.T) {
	results := []*models.A2AServer{
		makeA2AServer("10.0.0.1", 80, "system-admin-agent", "1.0", []string{"schedule_system_commands"}, true),
		makeA2AServer("10.0.0.2", 80, "system-admin-agent", "1.0", []string{"schedule_system_commands"}, true),
		makeA2AServer("10.0.0.3", 80, "system-admin-agent", "1.0", []string{"schedule_system_commands"}, false),
		makeA2AServer("10.0.0.9", 80, "OmniRoute AI Gateway", "2.1", []string{"smart-routing"}, false),
	}

	clusters := clusterA2AResults(results)
	if len(clusters) != 2 {
		t.Fatalf("clusters = %d, want 2", len(clusters))
	}
	// 部署数降序：system-admin-agent (3) 在前
	if clusters[0].ProductName != "system-admin-agent" || clusters[0].Count != 3 {
		t.Fatalf("cluster[0] = %+v, want system-admin-agent count=3", clusters[0])
	}
	if clusters[0].NoAuthCount != 2 {
		t.Fatalf("cluster[0].NoAuthCount = %d, want 2", clusters[0].NoAuthCount)
	}
	if clusters[1].ProductName != "OmniRoute AI Gateway" || clusters[1].Count != 1 {
		t.Fatalf("cluster[1] = %+v, want OmniRoute count=1", clusters[1])
	}
}

func TestClusterKeyDistinguishesVersionAndSkills(t *testing.T) {
	same1 := makeA2AServer("10.0.0.1", 80, "agent", "1.0", []string{"a", "b"}, false)
	same2 := makeA2AServer("10.0.0.2", 80, "agent", "1.0", []string{"b", "a"}, false) // skill 顺序不同应视为同簇
	diffVer := makeA2AServer("10.0.0.3", 80, "agent", "2.0", []string{"a", "b"}, false)
	diffSkill := makeA2AServer("10.0.0.4", 80, "agent", "1.0", []string{"a", "c"}, false)

	if a2aClusterKey(same1) != a2aClusterKey(same2) {
		t.Fatal("skill 顺序不同的同款卡片 key 应相同")
	}
	if a2aClusterKey(same1) == a2aClusterKey(diffVer) {
		t.Fatal("版本不同应产生不同 key")
	}
	if a2aClusterKey(same1) == a2aClusterKey(diffSkill) {
		t.Fatal("skill 集合不同应产生不同 key")
	}
}

func TestMultiDeploymentClustersFiltersSingletons(t *testing.T) {
	results := []*models.A2AServer{
		makeA2AServer("10.0.0.1", 80, "dup", "1.0", []string{"x"}, false),
		makeA2AServer("10.0.0.2", 80, "dup", "1.0", []string{"x"}, false),
		makeA2AServer("10.0.0.3", 80, "solo", "1.0", []string{"y"}, false),
	}
	multi := multiDeploymentClusters(results)
	if len(multi) != 1 || multi[0].ProductName != "dup" || multi[0].Count != 2 {
		t.Fatalf("multiDeploymentClusters = %+v, want only dup count=2", multi)
	}
}

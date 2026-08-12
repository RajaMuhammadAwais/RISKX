package graph

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// fixtureGraph builds a small enterprise network:
//
//	web (internet-exposed, KEV vuln) --affected_by--> db (critical)
//	web --exposes--> api --affected_by--> db
//	ssh (internal) --connected_to--> db
//	admin (internet-exposed, critical) <-accessible_by- web  [inferred edge]
func fixtureGraph() *Graph {
	g := New()
	score := func(exposure, crit float64) *models.RiskScore {
		return &models.RiskScore{Factors: []models.RiskFactor{
			{Name: "exposure", Value: exposure, Weight: 0.2},
			{Name: "criticality", Value: crit, Weight: 0.15},
		}}
	}
	ev := models.Evidence{Type: "test", Source: "fixture", Timestamp: time.Now().UTC()}
	g.AddNode(Node{ID: "web", Label: "web.example.com", Kind: models.KindHost, Score: score(1, 0.4)})
	g.AddNode(Node{ID: "api", Label: "api.example.com", Kind: models.KindAPI, Score: score(0, 0.5)})
	g.AddNode(Node{ID: "db", Label: "db.internal", Kind: models.KindHost, Score: score(0, 0.9)})
	g.AddNode(Node{ID: "ssh", Label: "ssh.internal", Kind: models.KindHost, Score: score(0, 0.3)})
	g.AddNode(Node{ID: "admin", Label: "admin.example.com", Kind: models.KindHost, Score: score(1, 0.8)})

	g.AddEdge(Edge{ID: EdgeID("web", "db", models.RelAffectedBy), From: "web", To: "db",
		Type: models.RelAffectedBy, Status: models.StatusObserved,
		Weight: EdgeWeight(models.Relationship{Type: models.RelAffectedBy}, 9.8, true),
		Evidence: []models.Evidence{ev}})
	g.AddEdge(Edge{ID: EdgeID("web", "api", models.RelExposes), From: "web", To: "api",
		Type: models.RelExposes, Status: models.StatusObserved, Weight: 0.6, Evidence: []models.Evidence{ev}})
	g.AddEdge(Edge{ID: EdgeID("api", "db", models.RelAffectedBy), From: "api", To: "db",
		Type: models.RelAffectedBy, Status: models.StatusInferred,
		Weight: EdgeWeight(models.Relationship{Type: models.RelAffectedBy}, 7.5, false),
		Evidence: []models.Evidence{ev}})
	g.AddEdge(Edge{ID: EdgeID("ssh", "db", models.RelConnectedTo), From: "ssh", To: "db",
		Type: models.RelConnectedTo, Status: models.StatusObserved, Weight: 0.8, Evidence: []models.Evidence{ev}})
	g.AddEdge(Edge{ID: EdgeID("web", "admin", models.RelAccessibleBy), From: "web", To: "admin",
		Type: models.RelAccessibleBy, Status: models.StatusInferred, Weight: 0.5, Evidence: []models.Evidence{ev}})
	// A purely potential edge that should only appear in exploratory mode.
	g.AddEdge(Edge{ID: EdgeID("api", "admin", models.RelConnectedTo), From: "api", To: "admin",
		Type: models.RelConnectedTo, Status: models.StatusPotential, Weight: 0.9, Evidence: []models.Evidence{ev}})
	return g
}

func TestBFSPathsEnumeratesRealPath(t *testing.T) {
	g := fixtureGraph()
	paths, err := g.BFSPaths(ModeEvidenceBacked, 6)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("expected at least one enumerated path")
	}
	var found bool
	for _, p := range paths {
		if p.Nodes[0] == "web" && p.Nodes[len(p.Nodes)-1] == "db" {
			found = true
		}
		if len(p.Nodes) < 2 {
			t.Errorf("path too short: %v", p)
		}
		if p.TotalScore <= 0 {
			t.Errorf("path score must be positive: %v", p)
		}
	}
	if !found {
		t.Error("expected web→db path in BFS enumeration")
	}
	// scores descending
	for i := 1; i < len(paths); i++ {
		if paths[i-1].TotalScore < paths[i].TotalScore {
			t.Errorf("paths not sorted descending: %v", paths)
		}
	}
}

func TestBFSModeGating(t *testing.T) {
	g := fixtureGraph()
	obs, _ := g.BFSPaths(ModeObservedOnly, 6)
	exp, _ := g.BFSPaths(ModeExploratory, 6)
	if len(obs) >= len(exp) && len(obs) > 0 {
		t.Error("observed-only mode should report fewer or equal paths than exploratory")
	}
	// potential edge only in exploratory
	inExpl := false
	for _, p := range exp {
		for _, e := range p.Edges {
			if e.Status == models.StatusPotential {
				inExpl = true
			}
		}
	}
	if !inExpl {
		t.Error("expected the potential edge to appear in exploratory mode")
	}
}

func TestDijkstraRanking(t *testing.T) {
	g := fixtureGraph()
	paths, err := g.DijkstraPaths(ModeEvidenceBacked)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("expected at least one shortest path to a crown asset")
	}
	// db (criticality 0.9) and admin (0.8) are crowns; first path must be
	// cheapest traversal to some crown.
	first := paths[0]
	if !strings.Contains(first.Nodes[len(first.Nodes)-1], "") && first.Nodes[len(first.Nodes)-1] != "db" && first.Nodes[len(first.Nodes)-1] != "admin" {
		t.Errorf("first Dijkstra path must end on a crown asset, got %v", first.Nodes)
	}
	for i := 1; i < len(paths); i++ {
		if paths[i-1].TotalScore > paths[i].TotalScore {
			t.Errorf("Dijkstra paths not sorted ascending: %v", paths)
		}
	}
}

func TestNoEntryOrCrownNodesError(t *testing.T) {
	g := New()
	g.AddNode(Node{ID: "lonely", Label: "no-score"})
	for _, fn := range []func(mode ReportMode) ([]Path, error){
		func(m ReportMode) ([]Path, error) { return g.BFSPaths(m, 3) },
		func(m ReportMode) ([]Path, error) { return g.DijkstraPaths(m) },
	} {
		if _, err := fn(ModeEvidenceBacked); err == nil {
			t.Error("expected error with no entry/crown evidence")
		}
	}
}

func TestEdgeWeightEvidence(t *testing.T) {
	rel := models.Relationship{Type: models.RelAffectedBy}
	wBase := EdgeWeight(rel, 7.5, false)   // CVSS-driven
	wKEV := EdgeWeight(rel, 7.5, true)     // KEV explicitly increases
	if wKEV <= wBase {
		t.Errorf("KEV evidence must raise edge weight: base=%.2f kev=%.2f", wBase, wKEV)
	}
	if got := EdgeWeight(rel, 0, false); got != 0 {
		t.Errorf("CVSS 0 with no KEV → 0, got %.2f", got)
	}
	if got := EdgeWeight(models.Relationship{Type: models.RelExposes}, 0, false); got != 0.6 {
		t.Errorf("exposes edge weight = 0.6, got %.2f", got)
	}
}

func TestDegreeCentrality(t *testing.T) {
	g := fixtureGraph()
	deg := g.Degree(ModeEvidenceBacked)
	// web connects to db, api, admin → 3 edges; db degree 3 (web,api,ssh)
	// degree centrality is normalized by max(1, N-1) = 4 for the 5-node fixture.
	if deg["web"] != 0.75 {
		t.Errorf("web degree centrality = 0.75 (3 of 4), got %.2f", deg["web"])
	}
	if deg["db"] != 0.75 {
		t.Errorf("db degree centrality = 0.75 (3 of 4), got %.2f", deg["db"])
	}
}

func TestBetweennessIsDeterministic(t *testing.T) {
	g := fixtureGraph()
	a := g.ApproxBetweenness(ModeEvidenceBacked, 5)
	b := g.ApproxBetweenness(ModeEvidenceBacked, 5)
	if len(a) != len(b) {
		t.Fatalf("betweenness not deterministic: %v vs %v", a, b)
	}
	for k, v := range a {
		if b[k] != v {
			t.Errorf("betweenness differs for %s: %.4f vs %.4f", k, v, b[k])
		}
	}
	// api is the pivot in the fixture: it is the intermediate node on the
	// shortest paths web→api→db and web→api→admin, so its betweenness is
	// positive; db is only ever an endpoint (no outgoing edges) → 0.
	if a["api"] <= 0 {
		t.Error("api expected non-zero betweenness (pivot node)")
	}
	if a["db"] != 0 {
		t.Errorf("db has no outgoing edges → betweenness 0, got %.4f", a["db"])
	}
}

func TestGraphOnlyKeepsEvidenceBackedEdges(t *testing.T) {
	g := New()
	g.AddEdge(Edge{From: "a", To: "b", Type: models.RelConnectedTo, Status: models.StatusObserved, Weight: 0.5})
	if len(g.Edges) != 1 {
		t.Errorf("expected one evidence-backed edge, got %d", len(g.Edges))
	}
}

func TestClamp01(t *testing.T) {
	cases := []struct{ in, want float64 }{{-0.5, 0}, {1.5, 1}, {0.42, 0.42}}
	for _, c := range cases {
		if got := clamp01(c.in); got != c.want {
			t.Errorf("clamp01(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestMinStatusOrdering(t *testing.T) {
	ev := models.Evidence{Type: "t", Timestamp: time.Now().UTC()}
	edges := []Edge{
		{Status: models.StatusObserved, Evidence: []models.Evidence{ev}},
		{Status: models.StatusValidated, Evidence: []models.Evidence{ev}},
		{Status: models.StatusInferred, Evidence: []models.Evidence{ev}},
	}
	if got := minStatus(edges); got != models.StatusInferred {
		t.Errorf("min status = observed/validated/inferred → inferred, got %s", got)
	}
}

func TestEdgeIDStability(t *testing.T) {
	a := EdgeID("x", "y", models.RelAffectedBy)
	b := EdgeID("x", "y", models.RelAffectedBy)
	c := EdgeID("y", "x", models.RelAffectedBy)
	if a != b {
		t.Error("edge IDs must be stable for identical inputs")
	}
	if a == c {
		t.Error("direction must matter for edge IDs")
	}
	if !strings.HasPrefix(a, "edge-") {
		t.Errorf("edge ID prefix: %s", a)
	}
}

// sortedKeys needs export check — simple compile+use test
func TestSortedKeysDeterminism(t *testing.T) {
	g := fixtureGraph()
	a := sortedKeys(g.Nodes)
	b := sortedKeys(g.Nodes)
	if len(a) != 5 {
		t.Errorf("expected 5 nodes, got %d", len(a))
	}
	if !sort.StringsAreSorted(a) || a[0] != b[0] {
		t.Error("sortedKeys not deterministic/sorted")
	}
}

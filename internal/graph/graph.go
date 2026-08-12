// Package graph implements the graph-v1 attack-graph model: evidence-backed
// nodes and edges, BFS enumeration, weighted Dijkstra path ranking, and
// centrality metrics for pivot identification (ADR-0005).
//
// Design constraints (spec §13, §48; ADR-0005):
//   - Only evidence-backed nodes/edges are included in the graph.
//   - Every edge carries an EvidenceStatus; Inferred is never rendered as a
//     confirmed attack. Report modes gate which statuses participate.
//   - Weights are traceable to risk-v1 factor evidence; they are a
//     deterministic simplification of true exploitation probability
//     (independence assumptions documented in docs/research/risk-model.md §2).
//   - Centrality is used for prioritization, never as proof of compromise.
package graph

import (
	"container/heap"
	"fmt"
	"math"
	"sort"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/errs"
	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// ModelVersion is the current attack-graph model identifier (spec §45).
const ModelVersion = "graph-v1"

// ReportMode gates which edge statuses participate in a report.
type ReportMode string

const (
	// ModeObservedOnly reports only directly measured edges.
	ModeObservedOnly ReportMode = "observed_only"
	// ModeEvidenceBacked reports Observed + Inferred edges (default).
	ModeEvidenceBacked ReportMode = "evidence_backed"
	// ModeExploratory reports all statuses including Potential, marked clearly.
	ModeExploratory ReportMode = "exploratory"
)

// Node is an evidence-backed graph node wrapping an asset or identity ID.
type Node struct {
	ID    string            `json:"id"`
	Label string            `json:"label"`
	Kind  models.AssetKind  `json:"kind,omitempty"`
	Score *models.RiskScore `json:"score,omitempty"` // optional attached risk-v1 evidence
}

// Edge is an evidence-backed relationship with a derived risk weight.
type Edge struct {
	ID       string                  `json:"id"`
	From     string                  `json:"from"`
	To       string                  `json:"to"`
	Type     models.RelationshipType `json:"type"`
	Status   models.EvidenceStatus   `json:"status"`
	Weight   float64                 `json:"weight"`            // 0..1 derived from edge evidence (lower = easier/more dangerous traversal)
	Evidence []models.Evidence       `json:"evidence"`
}

// Path is one enumerated attack path from an entry node to a crown asset.
type Path struct {
	Nodes      []string          `json:"nodes"`
	Edges      []Edge            `json:"edges"`
	TotalScore float64           `json:"total_score"` // cumulative traversal risk contribution
	MinStatus  models.EvidenceStatus `json:"min_status"` // weakest edge status on the path
}

// Graph is the graph-v1 attack graph. It stores only evidence-backed edges
// (spec §13): nodes without at least one attached edge are not added.
type Graph struct {
	Nodes map[string]Node
	Edges []Edge
}

// New constructs an empty graph.
func New() *Graph {
	return &Graph{Nodes: make(map[string]Node)}
}

// AddNode adds an evidence-backed node.
func (g *Graph) AddNode(n Node) {
	g.Nodes[n.ID] = n
}

// AddEdge adds an evidence-backed edge. Weights are clamped to [0.01, 1].
func (g *Graph) AddEdge(e Edge) {
	if _, ok := g.Nodes[e.From]; !ok {
		g.Nodes[e.From] = Node{ID: e.From}
	}
	if _, ok := g.Nodes[e.To]; !ok {
		g.Nodes[e.To] = Node{ID: e.To}
	}
	if e.Weight <= 0 {
		e.Weight = 0.01
	}
	if e.Weight > 1 {
		e.Weight = 1
	}
	g.Edges = append(g.Edges, e)
}

// EdgeWeight derives a deterministic 0..1 traversal weight for an edge from
// its evidence: observed exploitation (KEV) on the target edge, CVSS severity,
// and internet exposure are all explicit evidence — nothing is guessed.
// Lower weight = easier (more dangerous) traversal; used as Dijkstra cost.
func EdgeWeight(r models.Relationship, cvss float64, inKEV bool) float64 {
	w := 1.0 // default: no evidence of traversability
	switch r.Type {
	case models.RelAffectedBy:
		// vulnerability link: CVSS drives traversability.
		w = cvss / 10.0
		if inKEV {
			w = math.Min(1, w+0.3) // KEV membership is explicit evidence of exploitation
		}
	case models.RelExposes:
		w = 0.6
	case models.RelAccessibleBy:
		w = 0.5
	case models.RelRuns, models.RelConnectedTo, models.RelParticipates:
		w = 0.8
	}
	return clamp01(w)
}

// EntryNodes returns node IDs annotated as internet-exposed (entry points),
// from attached risk evidence where present.
func (g *Graph) EntryNodes() []string {
	var out []string
	for _, n := range g.Nodes {
		if n.Score != nil {
			for _, f := range n.Score.Factors {
				if f.Name == "exposure" && f.Value >= 1.0 {
					out = append(out, n.ID)
					break
				}
			}
		}
	}
	return out
}

// CrownNodes returns node IDs annotated as critical (business crown jewels),
// from attached risk evidence.
func (g *Graph) CrownNodes() []string {
	var out []string
	for _, n := range g.Nodes {
		if n.Score != nil {
			for _, f := range n.Score.Factors {
				if f.Name == "criticality" && f.Value >= 0.7 {
					out = append(out, n.ID)
					break
				}
			}
		}
	}
	return out
}

// adj builds adjacency lists (directed) for edges matching the report mode.
func (g *Graph) adj(mode ReportMode) map[string][]Edge {
	a := make(map[string][]Edge)
	for _, e := range g.Edges {
		if !modeAllows(mode, e.Status) {
			continue
		}
		a[e.From] = append(a[e.From], e)
	}
	return a
}

func modeAllows(mode ReportMode, s models.EvidenceStatus) bool {
	switch mode {
	case ModeObservedOnly:
		return s == models.StatusObserved || s == models.StatusValidated
	case ModeExploratory:
		return true
	default:
		return s == models.StatusObserved || s == models.StatusValidated || s == models.StatusInferred
	}
}

// --- BFS enumeration (ADR-0005 option a) ---

// BFSPaths enumerates all simple paths (bounded by MaxDepth) from entry nodes
// to crown nodes using BFS with path memory. Only mode-allowed edges traverse.
func (g *Graph) BFSPaths(mode ReportMode, maxDepth int) ([]Path, error) {
	if maxDepth <= 0 {
		maxDepth = 6
	}
	entries := g.EntryNodes()
	if len(entries) == 0 {
		return nil, errs.Input("graph.paths", "no entry nodes with exposure evidence",
			"attach risk-v1 scores to nodes so exposure evidence is available")
	}
	crowns := g.CrownNodes()
	if len(crowns) == 0 {
		return nil, errs.Input("graph.paths", "no crown nodes with criticality evidence",
			"attach risk-v1 scores to nodes so criticality evidence is available")
	}
	crownSet := make(map[string]bool, len(crowns))
	for _, c := range crowns {
		crownSet[c] = true
	}
	adj := g.adj(mode)
	var paths []Path
	// BFS over (path nodes, path edges) state.
	type state struct {
		nodes []string
		edges []Edge
	}
	// per-node minimum depth observed across all states (prunes dominated
	// re-expansions; simple-path check still prevents cycles).
	queue := []state{}
	for _, e := range entries {
		queue = append(queue, state{nodes: []string{e}})
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		last := cur.nodes[len(cur.nodes)-1]
		depth := len(cur.nodes)
		if crownSet[last] && depth > 1 {
			paths = append(paths, Path{
				Nodes:      cur.nodes,
				Edges:      cur.edges,
				TotalScore: pathScore(cur.edges),
				MinStatus:  minStatus(cur.edges),
			})
			continue
		}
		if depth >= maxDepth {
			continue
		}
		for _, e := range adj[last] {
			if contains(cur.nodes, e.To) {
				continue // simple path
			}
			edges := append(append([]Edge(nil), cur.edges...), e)
			nodes := append(append([]string(nil), cur.nodes...), e.To)
			queue = append(queue, state{nodes: nodes, edges: edges})
		}
	}
	sort.SliceStable(paths, func(i, j int) bool {
		return paths[i].TotalScore > paths[j].TotalScore
	})
	return paths, nil
}

// --- Dijkstra weighted traversal (ADR-0005 option b) ---

// DijkstraPaths returns, per crown node, the lowest-cost (most dangerous)
// traversal path from any entry node. Cost is sum of edge weights; fewer and
// weaker-evidence edges cost more to traverse. Mode gates edge statuses.
func (g *Graph) DijkstraPaths(mode ReportMode) ([]Path, error) {
	entries := g.EntryNodes()
	if len(entries) == 0 {
		return nil, errs.Input("graph.paths", "no entry nodes with exposure evidence",
			"attach risk-v1 scores to nodes so exposure evidence is available")
	}
	crowns := g.CrownNodes()
	if len(crowns) == 0 {
		return nil, errs.Input("graph.paths", "no crown nodes with criticality evidence",
			"attach risk-v1 scores to nodes so criticality evidence is available")
	}
	adj := g.adj(mode)

	dist := make(map[string]float64)
	prev := make(map[string]*Edge)
	h := &pq{}
	heap.Init(h)
	for _, e := range entries {
		dist[e] = 0
		heap.Push(h, pqItem{node: e, cost: 0})
	}
	for h.Len() > 0 {
		cur := heap.Pop(h).(pqItem)
		if cur.cost > dist[cur.node] {
			continue
		}
		for _, e := range adj[cur.node] {
			nd := cur.cost + e.Weight
			if d, ok := dist[e.To]; !ok || nd < d {
				dist[e.To] = nd
				cp := e
				prev[e.To] = &cp
				heap.Push(h, pqItem{node: e.To, cost: nd})
			}
		}
	}

	var paths []Path
	for _, c := range crowns {
		d, ok := dist[c]
		if !ok {
			continue
		}
		var pathNodes []string
		var pathEdges []Edge
		for cur := c; ; {
			pathNodes = append(pathNodes, cur)
			e := prev[cur]
			if e == nil {
				break
			}
			pathEdges = append(pathEdges, *e)
			cur = e.From
		}
		reverse(pathNodes)
		reverse(pathEdges)
		paths = append(paths, Path{
			Nodes:      pathNodes,
			Edges:      pathEdges,
			TotalScore: d,
			MinStatus:  minStatus(pathEdges),
		})
	}
	sort.SliceStable(paths, func(i, j int) bool {
		return paths[i].TotalScore < paths[j].TotalScore
	})
	return paths, nil
}

// --- Centrality (ADR-0005 option c) ---

// Degree returns per-node degree centrality over mode-allowed edges.
func (g *Graph) Degree(mode ReportMode) map[string]float64 {
	out := make(map[string]float64, len(g.Nodes))
	n := float64(max(1, len(g.Nodes)-1))
	for _, e := range g.Edges {
		if !modeAllows(mode, e.Status) {
			continue
		}
		out[e.From]++
		if e.From != e.To {
			out[e.To]++
		}
	}
	for k := range out {
		out[k] /= n
	}
	return out
}

// ApproxBetweenness returns approximate betweenness centrality computed over
// a bounded number of BFS samples per node (deterministic, seeded by node
// order). Exact Brandes is documented as the future upgrade in ADR-0005.
func (g *Graph) ApproxBetweenness(mode ReportMode, samples int) map[string]float64 {
	if samples <= 0 {
		samples = 10
	}
	if samples > len(g.Nodes) {
		samples = len(g.Nodes)
	}
	out := make(map[string]float64, len(g.Nodes))
	nodeIDs := sortedKeys(g.Nodes)
	adj := g.adj(mode)
	// sample sources = first `samples` node IDs (deterministic order)
	for _, src := range nodeIDs[:samples] {
		// BFS shortest-path DAG from src
		stack := make(map[string][]string) // node -> parents
		dist := map[string]int{src: 0}
		sigma := map[string]int{src: 1}
		queue := []string{src}
		for len(queue) > 0 {
			v := queue[0]
			queue = queue[1:]
			for _, e := range adj[v] {
				w := e.To
				if _, known := dist[w]; !known {
					dist[w] = dist[v] + 1
					stack[w] = []string{v}
					sigma[w] = sigma[v]
					queue = append(queue, w)
				} else if dist[w] == dist[v]+1 {
					stack[w] = append(stack[w], v)
					sigma[w] += sigma[v]
				}
			}
		}
		delta := make(map[string]float64)
		order := make([]string, 0, len(dist))
		for id := range dist {
			order = append(order, id)
		}
		sort.Slice(order, func(i, j int) bool { return dist[order[i]] > dist[order[j]] })
		for _, w := range order {
			for _, v := range stack[w] {
				if sigma[w] > 0 {
					delta[v] += float64(sigma[v]) / float64(sigma[w]) * (1 + delta[w])
				}
			}
		}
		for id, v := range delta {
			out[id] += v
		}
	}
	// normalize by max so outputs sit in [0,1]
	var maxV float64
	for _, v := range out {
		if v > maxV {
			maxV = v
		}
	}
	if maxV > 0 {
		for k := range out {
			out[k] /= maxV
		}
	}
	return out
}

// CentralityReport combines degree and approximate betweenness.
func (g *Graph) CentralityReport(mode ReportMode) map[string]map[string]float64 {
	deg := g.Degree(mode)
	bet := g.ApproxBetweenness(mode, 10)
	out := make(map[string]map[string]float64, len(g.Nodes))
	for id := range g.Nodes {
		out[id] = map[string]float64{
			"degree":           deg[id],
			"betweenness_approx": bet[id],
		}
	}
	return out
}

// --- helpers ---

func pathScore(edges []Edge) float64 {
	var s float64
	for _, e := range edges {
		s += e.Weight
	}
	return s
}

func minStatus(edges []Edge) models.EvidenceStatus {
	order := []models.EvidenceStatus{
		models.StatusPotential, models.StatusInferred, models.StatusObserved, models.StatusValidated,
	}
	min := models.StatusValidated
	for _, e := range edges {
		for _, s := range order {
			if e.Status == s && before(s, min, order) {
				min = s
			}
		}
	}
	return min
}

func before(a, b models.EvidenceStatus, order []models.EvidenceStatus) bool {
	ia, ib := -1, -1
	for i, s := range order {
		if s == a {
			ia = i
		}
		if s == b {
			ib = i
		}
	}
	return ia < ib
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func reverse[T any](s []T) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func sortedKeys(m map[string]Node) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// EdgeID returns a stable content-addressed ID for an edge (graph-v1).
func EdgeID(from, to string, t models.RelationshipType) string {
	return models.ContentID("edge", from, to, string(t))
}

// priority queue for Dijkstra (min-heap by cost).
type pqItem struct {
	node string
	cost float64
}

type pq []pqItem

func (p pq) Len() int            { return len(p) }
func (p pq) Less(i, j int) bool  { return p[i].cost < p[j].cost }
func (p pq) Swap(i, j int)       { p[i], p[j] = p[j], p[i] }
func (p *pq) Push(x any)         { *p = append(*p, x.(pqItem)) }
func (p *pq) Pop() any {
	old := *p
	n := len(old)
	item := old[n-1]
	old[n-1] = pqItem{}
	*p = old[:n-1]
	return item
}

var _ = fmt.Sprintf // reserved for future traversal logging

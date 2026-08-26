package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"kubegraph/internal/graph"
	"kubegraph/internal/store"
)

const cluster = "test-cluster"

func nid(uid string) graph.NodeID { return graph.NodeID{ClusterID: cluster, UID: uid} }

func node(uid, kind string) graph.Node {
	return graph.Node{ID: nid(uid), Kind: kind, Name: uid, Origin: graph.OriginObserved}
}

func testHandler() *Handler {
	s := store.New()
	s.Load(
		[]graph.Node{
			node("d1", "Deployment"), node("rs1", "ReplicaSet"), node("p1", "Pod"),
		},
		[]graph.Edge{
			{From: nid("rs1"), To: nid("d1"), Type: graph.EdgeOwnedBy},
			{From: nid("p1"), To: nid("rs1"), Type: graph.EdgeOwnedBy},
		},
	)
	return New(s)
}

func do(h *Handler, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)
	return rec
}

func TestEgoOK(t *testing.T) {
	rec := do(testHandler(), "/ego?cluster=test-cluster&uid=d1&depth=2")
	if rec.Code != http.StatusOK {
		t.Fatalf("status attendu 200, obtenu %d (%s)", rec.Code, rec.Body.String())
	}

	var got egoDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("JSON invalide : %v", err)
	}
	if got.Root != "test-cluster/d1" {
		t.Errorf("root attendu 'test-cluster/d1', obtenu %q", got.Root)
	}
	if len(got.Nodes) != 3 {
		t.Fatalf("nœuds attendus 3, obtenu %d", len(got.Nodes))
	}
	// Le nœud racine doit être au cercle 0 avec l'id attendu.
	if got.Nodes[0].ID != "test-cluster/d1" || got.Nodes[0].Degree != 0 {
		t.Errorf("racine incorrecte : %+v", got.Nodes[0])
	}
	if len(got.Edges) != 2 {
		t.Errorf("arêtes attendues 2, obtenu %d", len(got.Edges))
	}
}

func TestEgoParamsManquants(t *testing.T) {
	rec := do(testHandler(), "/ego?cluster=test-cluster")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status attendu 400, obtenu %d", rec.Code)
	}
}

func TestEgoIntrouvable(t *testing.T) {
	rec := do(testHandler(), "/ego?cluster=test-cluster&uid=absent")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status attendu 404, obtenu %d", rec.Code)
	}
}

func TestEgoDepthInvalide(t *testing.T) {
	rec := do(testHandler(), "/ego?cluster=test-cluster&uid=d1&depth=-3")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status attendu 400, obtenu %d", rec.Code)
	}
}

func TestHealth(t *testing.T) {
	rec := do(testHandler(), "/healthz")
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Errorf("healthz incorrect : %d %q", rec.Code, rec.Body.String())
	}
}

func TestNodesListe(t *testing.T) {
	rec := do(testHandler(), "/nodes")
	if rec.Code != http.StatusOK {
		t.Fatalf("status attendu 200, obtenu %d", rec.Code)
	}
	var got []listNodeDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("JSON invalide : %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("nœuds attendus 3, obtenu %d", len(got))
	}
}

func TestGraph(t *testing.T) {
	rec := do(testHandler(), "/graph")
	if rec.Code != http.StatusOK {
		t.Fatalf("status attendu 200, obtenu %d", rec.Code)
	}
	var g struct {
		Nodes []map[string]any `json:"nodes"`
		Edges []map[string]any `json:"edges"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &g); err != nil {
		t.Fatalf("JSON invalide : %v", err)
	}
	if len(g.Nodes) != 3 || len(g.Edges) != 2 {
		t.Fatalf("attendu 3 nœuds / 2 arêtes, obtenu %d / %d", len(g.Nodes), len(g.Edges))
	}
}

func TestCORS(t *testing.T) {
	// L'en-tête CORS doit être présent (frontend servi depuis une autre origine).
	req := httptest.NewRequest(http.MethodGet, "/ego?cluster=test-cluster&uid=d1", nil)
	rec := httptest.NewRecorder()
	testHandler().Handler().ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("en-tête CORS attendu '*', obtenu %q", got)
	}
	// Le préflight OPTIONS doit répondre 204.
	pre := httptest.NewRequest(http.MethodOptions, "/ego", nil)
	prec := httptest.NewRecorder()
	testHandler().Handler().ServeHTTP(prec, pre)
	if prec.Code != http.StatusNoContent {
		t.Errorf("préflight OPTIONS attendu 204, obtenu %d", prec.Code)
	}
}

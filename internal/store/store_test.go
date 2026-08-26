package store

import (
	"testing"

	"kubegraph/internal/graph"
)

const cluster = "test-cluster"

func nid(uid string) graph.NodeID { return graph.NodeID{ClusterID: cluster, UID: uid} }

func node(uid, kind string) graph.Node {
	return graph.Node{ID: nid(uid), Kind: kind, Origin: graph.OriginObserved}
}

// chaîne : Deployment d1 <- ReplicaSet rs1 <- Pod p1 ; Service s1 -> Pod p1 ;
// Ingress i1 -> Service s1.
func fixture() *Store {
	s := New()
	s.Load(
		[]graph.Node{
			node("d1", "Deployment"), node("rs1", "ReplicaSet"), node("p1", "Pod"),
			node("s1", "Service"), node("i1", "Ingress"),
		},
		[]graph.Edge{
			{From: nid("rs1"), To: nid("d1"), Type: graph.EdgeOwnedBy},
			{From: nid("p1"), To: nid("rs1"), Type: graph.EdgeOwnedBy},
			{From: nid("s1"), To: nid("p1"), Type: graph.EdgeSelects},
			{From: nid("i1"), To: nid("s1"), Type: graph.EdgeRoutesTo},
		},
	)
	return s
}

func degrees(sg SubGraph) map[string]int {
	m := make(map[string]int)
	for _, en := range sg.Nodes {
		m[en.Node.ID.UID] = en.Degree
	}
	return m
}

func TestEgoDepth1(t *testing.T) {
	sg, ok := fixture().Ego(nid("d1"), 1)
	if !ok {
		t.Fatal("nœud racine introuvable")
	}
	got := degrees(sg)
	// d1 (racine) + rs1 (premier cercle). Pas p1 (2e cercle).
	if len(got) != 2 {
		t.Fatalf("nœuds attendus : 2, obtenu : %d (%v)", len(got), got)
	}
	if got["d1"] != 0 || got["rs1"] != 1 {
		t.Errorf("cercles incorrects : %v", got)
	}
	if _, present := got["p1"]; present {
		t.Errorf("p1 ne devrait pas être dans le 1er cercle : %v", got)
	}
}

func TestEgoDepth2(t *testing.T) {
	sg, _ := fixture().Ego(nid("d1"), 2)
	got := degrees(sg)
	// d1(0), rs1(1), p1(2).
	if got["d1"] != 0 || got["rs1"] != 1 || got["p1"] != 2 {
		t.Errorf("cercles incorrects : %v", got)
	}
	if _, present := got["s1"]; present {
		t.Errorf("s1 (3e cercle) ne devrait pas apparaître à depth 2 : %v", got)
	}
}

func TestEgoFromService(t *testing.T) {
	// Depuis le Service, le premier cercle est le Pod (relation SELECTS traversée
	// en sens inverse) — c'est tout l'intérêt de l'adjacence bidirectionnelle.
	sg, _ := fixture().Ego(nid("s1"), 1)
	got := degrees(sg)
	if got["s1"] != 0 || got["p1"] != 1 {
		t.Errorf("cercles incorrects : %v", got)
	}
}

func TestEgoInconnu(t *testing.T) {
	if _, ok := fixture().Ego(nid("absent"), 1); ok {
		t.Error("un nœud absent devrait retourner ok=false")
	}
}

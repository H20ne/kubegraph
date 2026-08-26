package live

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"kubegraph/internal/graph"
)

// TestCollectMappeLesNoeuds vérifie, sans cluster réel, que Collect liste les
// kinds attendus et mappe correctement chaque objet en nœud (id préfixé par le
// clusterID, kind, couche, origin).
func TestCollectMappeLesNoeuds(t *testing.T) {
	client := fake.NewSimpleClientset(
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
			Name: "web", Namespace: "default", UID: "d1",
			Labels: map[string]string{"app": "web"},
		}},
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
			Name: "web-5f", Namespace: "default", UID: "rs1",
		}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: "web-5f-abc", Namespace: "default", UID: "p1",
		}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{
			Name: "web-svc", Namespace: "default", UID: "s1",
		}},
		&networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{
			Name: "web-ing", Namespace: "default", UID: "i1",
		}},
	)

	s := NewWithClient(client, "test-cluster")

	nodes, edges, err := s.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect a échoué : %v", err)
	}
	if len(edges) != 0 {
		t.Fatalf("arêtes attendues : 0 (étape 3), obtenu : %d", len(edges))
	}
	if len(nodes) != 5 {
		t.Fatalf("nœuds attendus : 5, obtenu : %d", len(nodes))
	}

	byName := make(map[string]graph.Node, len(nodes))
	for _, n := range nodes {
		byName[n.Name] = n
	}

	// Le Deployment : id, kind, couche, origin, labels.
	d, ok := byName["web"]
	if !ok {
		t.Fatal("nœud Deployment 'web' absent")
	}
	if d.ID.ClusterID != "test-cluster" || d.ID.UID != "d1" {
		t.Errorf("id Deployment incorrect : %+v", d.ID)
	}
	if d.Kind != "Deployment" || d.Layer != graph.LayerWorkload {
		t.Errorf("mapping Deployment incorrect : kind=%s layer=%s", d.Kind, d.Layer)
	}
	if d.Origin != graph.OriginObserved {
		t.Errorf("origin attendu observed, obtenu %s", d.Origin)
	}
	if d.Labels["app"] != "web" {
		t.Errorf("labels non propagés : %v", d.Labels)
	}

	// Le Service doit être en couche networking.
	if svc := byName["web-svc"]; svc.Layer != graph.LayerNetworking {
		t.Errorf("Service attendu en couche networking, obtenu %s", svc.Layer)
	}
	// L'Ingress aussi.
	if ing := byName["web-ing"]; ing.Kind != "Ingress" || ing.Layer != graph.LayerNetworking {
		t.Errorf("mapping Ingress incorrect : kind=%s layer=%s", ing.Kind, ing.Layer)
	}
}

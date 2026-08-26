package live

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"

	dynamicfake "k8s.io/client-go/dynamic/fake"

	"kubegraph/internal/graph"
)

// TestKedaCrossNamespace vérifie que, sans cluster réel, un ScaledObject KEDA
// produit bien : ScaledObject -> Deployment (SCALES) et Kafka -> ScaledObject
// (TRIGGERS), même quand le Kafka est dans un AUTRE namespace.
func TestKedaCrossNamespace(t *testing.T) {
	const cluster = "test-cluster"

	// Kafka dans le namespace "kafka", le workload dans "pipeline".
	cs := fake.NewSimpleClientset(
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "pipeline", UID: "d1"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "kafka", Namespace: "kafka", UID: "k1"}},
	)

	so := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "keda.sh/v1alpha1", "kind": "ScaledObject",
		"metadata": map[string]any{"name": "web-scaler", "namespace": "pipeline", "uid": "so1"},
		"spec": map[string]any{
			"scaleTargetRef": map[string]any{"name": "web"},
			"triggers": []any{
				map[string]any{"type": "kafka", "metadata": map[string]any{
					"bootstrapServers": "kafka.kafka:9092", "topic": "orders",
				}},
			},
		},
	}}
	dc := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{scaledObjectGVR: "ScaledObjectList"},
		so,
	)

	s := NewWithClients(cs, dc, cluster)
	nodes, edges, err := s.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect a échoué : %v", err)
	}

	// Le nœud ScaledObject existe.
	var hasSO bool
	for _, n := range nodes {
		if n.Kind == "ScaledObject" && n.ID.UID == "so1" && n.Namespace == "pipeline" {
			hasSO = true
		}
	}
	if !hasSO {
		t.Fatal("nœud ScaledObject 'so1' absent")
	}

	nid := func(uid string) graph.NodeID { return graph.NodeID{ClusterID: cluster, UID: uid} }
	want := map[graph.Edge]bool{
		{From: nid("so1"), To: nid("d1"), Type: graph.EdgeScales}:   false, // ScaledObject -> Deployment
		{From: nid("k1"), To: nid("so1"), Type: graph.EdgeTriggers}: false, // Kafka -> ScaledObject (cross-ns)
	}
	for _, e := range edges {
		if _, expected := want[e]; expected {
			want[e] = true
		}
	}
	for e, found := range want {
		if !found {
			t.Errorf("arête KEDA manquante : %+v", e)
		}
	}
}

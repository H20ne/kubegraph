package live

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"kubegraph/internal/graph"
)

func TestMatchService(t *testing.T) {
	keys := map[string]string{
		"verdict-layer": "v1", "verdict-layer.pipeline": "v1", "minio.minio": "m1", "minio": "m1",
	}
	cases := map[string]string{
		"http://verdict-layer:8080/api":              "v1",
		"verdict-layer:8080":                         "v1",
		"verdict-layer.pipeline.svc.cluster.local":   "v1",
		"verdict-layer":                              "v1",
		"https://minio.minio.svc.cluster.local:9000": "m1",
		"pas-un-service":                             "",
	}
	for in, want := range cases {
		got, _ := matchService(in, "pipeline", keys)
		if got != want {
			t.Errorf("matchService(%q) = %q, attendu %q", in, got, want)
		}
	}
}

// TestConfigDeps : llm-layer a VERDICT_URL dans son env -> arête USES vers le
// service verdict-layer.
func TestConfigDeps(t *testing.T) {
	const cluster = "test"
	spec := corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{
		Name: "app",
		Env:  []corev1.EnvVar{{Name: "VERDICT_URL", Value: "http://verdict-layer:8080"}},
	}}}}

	cs := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "llm-layer", Namespace: "pipeline", UID: "llm"},
			Spec:       appsv1.DeploymentSpec{Template: spec},
		},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "verdict-layer", Namespace: "pipeline", UID: "vsvc"}},
	)
	s := NewWithClient(cs, cluster)

	_, edges, err := s.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect : %v", err)
	}
	want := graph.Edge{
		From: graph.NodeID{ClusterID: cluster, UID: "llm"},
		To:   graph.NodeID{ClusterID: cluster, UID: "vsvc"},
		Type: graph.EdgeUses,
	}
	var found bool
	for _, e := range edges {
		if e == want {
			found = true
		}
	}
	if !found {
		t.Errorf("arête USES llm-layer -> verdict-layer manquante ; obtenu : %+v", edges)
	}
}

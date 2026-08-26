package resolve

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kubegraph/internal/graph"
)

// TestEdges vérifie la chaîne complète Deployment -> ReplicaSet -> Pod,
// un Service qui sélectionne le pod, et un Ingress qui route vers le service.
func TestEdges(t *testing.T) {
	const cluster = "test-cluster"

	o := Objects{
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default", UID: "d1"},
		}},
		ReplicaSets: []appsv1.ReplicaSet{{
			ObjectMeta: metav1.ObjectMeta{
				Name: "web-5f", Namespace: "default", UID: "rs1",
				OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "web", UID: "d1"}},
			},
		}},
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{
				Name: "web-5f-abc", Namespace: "default", UID: "p1",
				Labels:          map[string]string{"app": "web"},
				OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "web-5f", UID: "rs1"}},
			},
		}},
		Services: []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Name: "web-svc", Namespace: "default", UID: "s1"},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "web"}},
		}},
		Ingresses: []networkingv1.Ingress{{
			ObjectMeta: metav1.ObjectMeta{Name: "web-ing", Namespace: "default", UID: "i1"},
			Spec: networkingv1.IngressSpec{
				Rules: []networkingv1.IngressRule{{
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{{
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{Name: "web-svc"},
								},
							}},
						},
					},
				}},
			},
		}},
	}

	edges := Edges(cluster, o)

	want := map[graph.Edge]bool{
		{From: nid("rs1"), To: nid("d1"), Type: graph.EdgeOwnedBy}:  false, // ReplicaSet -> Deployment
		{From: nid("p1"), To: nid("rs1"), Type: graph.EdgeOwnedBy}:  false, // Pod -> ReplicaSet
		{From: nid("s1"), To: nid("p1"), Type: graph.EdgeSelects}:   false, // Service -> Pod
		{From: nid("i1"), To: nid("s1"), Type: graph.EdgeRoutesTo}:  false, // Ingress -> Service
	}

	for _, e := range edges {
		if _, expected := want[e]; expected {
			want[e] = true
		} else {
			t.Errorf("arête inattendue : %+v", e)
		}
	}
	for e, found := range want {
		if !found {
			t.Errorf("arête manquante : %+v", e)
		}
	}
}

func nid(uid string) graph.NodeID {
	return graph.NodeID{ClusterID: "test-cluster", UID: uid}
}

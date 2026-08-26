// Commande kubegraph — point d'entrée du hub (MVP).
// Étape 2 : connecte la source live et affiche le nombre de nœuds par kind.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"kubegraph/internal/api"
	"kubegraph/internal/source/live"
	"kubegraph/internal/store"
)

// version du binaire (à remplacer par une injection au build plus tard).
const version = "0.8.0-keda"

func main() {
	// kubeconfig via l'env KUBECONFIG, sinon règles par défaut (~/.kube/config).
	src, err := live.New(os.Getenv("KUBECONFIG"), "")
	if err != nil {
		log.Fatalf("source live : %v", err)
	}

	nodes, edges, err := src.Collect(context.Background())
	if err != nil {
		log.Fatalf("collecte : %v", err)
	}

	counts := make(map[string]int)
	for _, n := range nodes {
		counts[n.Kind]++
	}
	edgeCounts := make(map[string]int)
	for _, e := range edges {
		edgeCounts[string(e.Type)]++
	}

	fmt.Printf("kubegraph %s — cluster %q : %d nœuds, %d arêtes\n", version, src.ClusterID(), len(nodes), len(edges))
	for _, kind := range []string{"Deployment", "ReplicaSet", "Pod", "Service", "Ingress"} {
		fmt.Printf("  %-12s %d\n", kind, counts[kind])
	}
	fmt.Println("arêtes :")
	for _, t := range []string{"OWNED_BY", "SELECTS", "ROUTES_TO"} {
		fmt.Printf("  %-12s %d\n", t, edgeCounts[t])
	}

	// Charge le graphe en mémoire.
	st := store.New()
	st.Load(nodes, edges)

	// Démarre l'API HTTP.
	addr := os.Getenv("KUBEGRAPH_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	handler := api.New(st)
	log.Printf("API kubegraph sur %s — ex : /ego?cluster=%s&uid=<uid>&depth=2", addr, src.ClusterID())
	log.Fatal(http.ListenAndServe(addr, handler.Handler()))
}

// Commande kubegraph — point d'entrée du hub.
//
// Collecte l'état du cluster (source live), le charge en mémoire et sert l'API.
// Avec --agent (ou KUBEGRAPH_AGENT=1), lance EN PLUS l'agent conntrack DANS le
// même process : il lit la table de connexions du noyau et écrit directement
// dans le store — plus besoin d'un second terminal ni de token en mono-nœud.
// (nécessite les droits root pour lire /proc/net/nf_conntrack : lancer sous sudo.)
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"kubegraph/internal/api"
	"kubegraph/internal/conntrack"
	"kubegraph/internal/source/declared"
	"kubegraph/internal/source/live"
	"kubegraph/internal/store"
)

const version = "0.12.0-netpol"

func main() {
	agentMode := hasFlag("--agent") || os.Getenv("KUBEGRAPH_AGENT") == "1"

	src, err := live.New(os.Getenv("KUBECONFIG"), "")
	if err != nil {
		log.Fatalf("source live : %v", err)
	}

	nodes, edges, err := src.Collect(context.Background())
	if err != nil {
		log.Fatalf("collecte : %v", err)
	}

	// Source DÉCLARÉE (GitOps) optionnelle : dossier de YAML rendus. Calcule la
	// dérive « déclaré vs observé » (présence). Non bloquant.
	if gitDir := flagVal("--git-dir", "KUBEGRAPH_GITDIR"); gitDir != "" {
		if decl, derr := declared.Load(gitDir); derr != nil {
			log.Printf("source déclarée (%s) : %v (ignorée)", gitDir, derr)
		} else if len(decl) == 0 {
			log.Printf("source déclarée (%s) : 0 ressource déclarable lue — le dossier contient-il du YAML rendu (helm template / kustomize build / kubectl get -o yaml) ?", gitDir)
		} else {
			nodes = declared.ApplyDrift(src.ClusterID(), nodes, decl)
			var insync, missing, unmanaged int
			for _, n := range nodes {
				switch n.Drift {
				case "insync":
					insync++
				case "missing":
					missing++
				case "unmanaged":
					unmanaged++
				}
			}
			fmt.Printf("gitops : %d déclaré(s) lus · %d en phase · %d manquant(s) · %d hors-Git — active « mode GitOps » dans le dashboard\n", len(decl), insync, missing, unmanaged)
		}
	} else {
		fmt.Println("gitops : inactif — pour l'activer, fournis un dossier de YAML rendus : KUBEGRAPH_GITDIR=<dossier> ./run.sh  (génère-le vite avec ./run.sh --git-snapshot)")
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
	for _, kind := range []string{"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod", "Service", "Ingress", "NetworkPolicy", "HorizontalPodAutoscaler", "PersistentVolumeClaim", "PersistentVolume", "PodDisruptionBudget", "ServiceAccount", "Role", "ClusterRole", "Secret"} {
		if counts[kind] > 0 {
			fmt.Printf("  %-14s %d\n", kind, counts[kind])
		}
	}
	fmt.Println("arêtes :")
	for _, t := range []string{"OWNED_BY", "SELECTS", "ROUTES_TO", "USES", "ALLOWS", "SCALES", "TRIGGERS"} {
		if edgeCounts[t] > 0 {
			fmt.Printf("  %-12s %d\n", t, edgeCounts[t])
		}
	}

	st := store.New()
	st.Load(nodes, edges)

	// Points d'attention sécurité (structurels).
	findings := src.Findings()
	st.SetFindings(findings)
	if len(findings) > 0 {
		sevCount := map[string]int{}
		for _, f := range findings {
			sevCount[string(f.Severity)]++
		}
		fmt.Printf("sécurité : %d point(s) d'attention", len(findings))
		for _, s := range []string{"critical", "high", "medium", "low"} {
			if sevCount[s] > 0 {
				fmt.Printf(" · %d %s", sevCount[s], s)
			}
		}
		fmt.Println()
	}

	// Agent embarqué : lit conntrack et pousse les flux observés dans le store.
	if agentMode {
		go runEmbeddedAgent(st)
	}

	addr := os.Getenv("KUBEGRAPH_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	handler := api.New(st, os.Getenv("KUBEGRAPH_INGEST_TOKEN"))

	// Dashboard servi PAR le hub : plus besoin d'un serveur statique séparé.
	// Dossier : $KUBEGRAPH_WEB, sinon "web" à côté du binaire s'il existe.
	webDir := os.Getenv("KUBEGRAPH_WEB")
	if webDir == "" {
		if _, err := os.Stat("web/index.html"); err == nil {
			webDir = "web"
		}
	}
	if webDir != "" {
		handler.SetWebDir(webDir)
	}

	mode := "hub"
	if agentMode {
		mode = "hub + agent embarqué"
	}
	log.Printf("kubegraph (%s) sur %s — API /graph, /nodes, /ego", mode, addr)
	if webDir != "" {
		log.Printf("dashboard servi sur http://localhost%s/ (dossier %q)", addr, webDir)
	}
	log.Fatal(http.ListenAndServe(addr, handler.Handler()))
}

// runEmbeddedAgent lit la table conntrack toutes les 15 s et ajoute les flux
// observés au store. Écriture directe : ni HTTP ni token (même process).
func runEmbeddedAgent(st *store.Store) {
	const every = 15 * time.Second
	log.Printf("agent embarqué actif — source %s (root requis)", conntrack.Path)
	for {
		flows, err := conntrack.Read(conntrack.Path)
		if err != nil {
			log.Printf("agent embarqué : lecture conntrack : %v (lancer sous sudo ?)", err)
		} else {
			n := 0
			for _, fl := range flows {
				if st.AddFlow(fl.Src, fl.Dst) {
					n++
				}
			}
			if n > 0 {
				log.Printf("agent embarqué : %d nouveaux flux observés", n)
			}
		}
		time.Sleep(every)
	}
}

func hasFlag(f string) bool {
	for _, a := range os.Args[1:] {
		if a == f {
			return true
		}
	}
	return false
}

// flagVal lit la valeur d'un flag (--nom valeur ou --nom=valeur), sinon la
// variable d'environnement de repli.
func flagVal(name, env string) string {
	args := os.Args[1:]
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, name+"=") {
			return strings.TrimPrefix(a, name+"=")
		}
	}
	return os.Getenv(env)
}

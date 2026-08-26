// Agent kubegraph — capture le trafic RÉEL observé (option B) et le pousse au hub.
//
// Il lit périodiquement la table conntrack du noyau, en extrait des couples
// src->dst, et les POST à /flows. Toute la résolution IP->pod->workload se fait
// côté hub.
//
// Cet agent AUTONOME sert la version MULTI-NŒUDS (un DaemonSet par nœud qui
// pousse vers un hub distant). En MONO-NŒUD (lab), préfère le hub avec agent
// EMBARQUÉ : `sudo go run ./cmd/kubegraph --agent` (un seul process, pas de token).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"kubegraph/internal/conntrack"
)

func main() {
	hub := getenv("HUB_URL", "http://localhost:8080")
	token := os.Getenv("KUBEGRAPH_INGEST_TOKEN")
	interval := 15 * time.Second
	log.Printf("agent kubegraph — hub=%s intervalle=%s source=%s", hub, interval, conntrack.Path)

	for {
		flows, err := conntrack.Read(conntrack.Path)
		if err != nil {
			log.Printf("lecture conntrack : %v (l'agent a-t-il les droits root ?)", err)
		} else if len(flows) > 0 {
			if err := push(hub, token, flows); err != nil {
				log.Printf("envoi au hub : %v", err)
			} else {
				log.Printf("%d connexions envoyées", len(flows))
			}
		}
		time.Sleep(interval)
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func push(hub, token string, flows []conntrack.Flow) error {
	body, _ := json.Marshal(map[string][]conntrack.Flow{"flows": flows})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, strings.TrimRight(hub, "/")+"/flows", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Ingest-Token", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return &httpError{resp.StatusCode}
	}
	return nil
}

type httpError struct{ code int }

func (e *httpError) Error() string { return "hub a répondu " + http.StatusText(e.code) }

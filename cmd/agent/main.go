// Agent kubegraph — capture le trafic RÉEL observé (option B) et le pousse au hub.
//
// Il lit périodiquement /proc/net/nf_conntrack (table de connexions du noyau,
// standard, présente sous Calico), en extrait des couples src->dst, et les POST
// à /flows. Toute la résolution IP->pod->workload se fait côté hub.
//
// Lecture seule sur le système. En mono-nœud (lab), on le lance simplement à
// côté du hub : `sudo HUB_URL=http://localhost:8080 go run ./cmd/agent`.
// (sudo car /proc/net/nf_conntrack est en général réservé à root.)
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const conntrackPath = "/proc/net/nf_conntrack"

type flow struct {
	Src string `json:"src"`
	Dst string `json:"dst"`
}

func main() {
	hub := getenv("HUB_URL", "http://localhost:8080")
	token := os.Getenv("KUBEGRAPH_INGEST_TOKEN")
	interval := 15 * time.Second
	log.Printf("agent kubegraph — hub=%s intervalle=%s source=%s", hub, interval, conntrackPath)

	for {
		flows, err := readConntrack(conntrackPath)
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

// readConntrack parse le fichier conntrack et retourne des couples src->dst
// dédupliqués. Pour chaque ligne, on prend le tuple original (src->dst) et le
// src du tuple réponse (le vrai pod côté serveur, après DNAT du ClusterIP).
func readConntrack(path string) ([]flow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := map[flow]struct{}{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		var srcs, dsts []string
		for _, tok := range strings.Fields(line) {
			if v, ok := strings.CutPrefix(tok, "src="); ok {
				srcs = append(srcs, v)
			} else if v, ok := strings.CutPrefix(tok, "dst="); ok {
				dsts = append(dsts, v)
			}
		}
		if len(srcs) < 1 || len(dsts) < 1 {
			continue
		}
		add := func(a, b string) {
			if a == "" || b == "" || a == b || skip(a) || skip(b) {
				return
			}
			seen[flow{Src: a, Dst: b}] = struct{}{}
		}
		// tuple original : client -> destination (souvent un ClusterIP)
		add(srcs[0], dsts[0])
		// src du tuple réponse : le pod serveur réel (après DNAT)
		if len(srcs) >= 2 {
			add(srcs[0], srcs[1])
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	out := make([]flow, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	return out, nil
}

// skip écarte les adresses non pertinentes (loopback, non IPv4 basiques).
func skip(ip string) bool {
	if strings.HasPrefix(ip, "127.") || ip == "::1" {
		return true
	}
	if strings.Contains(ip, ":") { // IPv6 — hors périmètre pour l'instant
		return true
	}
	return false
}

func push(hub, token string, flows []flow) error {
	body, _ := json.Marshal(map[string][]flow{"flows": flows})
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

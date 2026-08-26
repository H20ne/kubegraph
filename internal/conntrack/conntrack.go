// Package conntrack lit la table de connexions du noyau (/proc/net/nf_conntrack)
// et en extrait des couples src->dst. Partagé par l'agent autonome (cmd/agent)
// et par le hub en mode agent embarqué (cmd/kubegraph --agent).
//
// Lecture seule sur le système. /proc/net/nf_conntrack est en général réservé à
// root : l'appelant doit avoir les droits (sudo).
package conntrack

import (
	"bufio"
	"os"
	"strings"
)

// Path est l'emplacement standard de la table conntrack (présent sous Calico).
const Path = "/proc/net/nf_conntrack"

// Flow est une connexion observée src -> dst (tags JSON pour l'API /flows).
type Flow struct {
	Src string `json:"src"`
	Dst string `json:"dst"`
}

// Read parse le fichier conntrack et retourne des couples src->dst dédupliqués.
// Pour chaque ligne, on prend le tuple original (src->dst) et le src du tuple
// réponse (le vrai pod côté serveur, après DNAT du ClusterIP).
func Read(path string) ([]Flow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := map[Flow]struct{}{}
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
			seen[Flow{Src: a, Dst: b}] = struct{}{}
		}
		add(srcs[0], dsts[0]) // client -> destination (souvent un ClusterIP)
		if len(srcs) >= 2 {
			add(srcs[0], srcs[1]) // src du tuple réponse : pod serveur réel (post-DNAT)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	out := make([]Flow, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	return out, nil
}

// skip écarte les adresses non pertinentes (loopback, IPv6 pour l'instant).
func skip(ip string) bool {
	if strings.HasPrefix(ip, "127.") || ip == "::1" {
		return true
	}
	if strings.Contains(ip, ":") { // IPv6 — hors périmètre
		return true
	}
	return false
}

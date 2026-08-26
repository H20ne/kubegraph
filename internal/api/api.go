// Package api expose le graphe en HTTP. Le frontend appelle /ego à chaque clic
// pour récupérer le sous-graphe autour d'un nœud, en JSON prêt pour Cytoscape.
package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"kubegraph/internal/graph"
	"kubegraph/internal/store"
)

// maxDepth borne la profondeur pour éviter qu'un client demande un graphe géant.
const maxDepth = 6

// Handler sert les routes au-dessus d'un store.
type Handler struct {
	store       *store.Store
	ingestToken string // si non vide, exigé sur POST /flows (header X-Ingest-Token)
	webDir      string // si non vide, sert le dashboard statique à la racine "/"
}

// New construit le handler. token vide = ingestion ouverte (lab).
func New(s *store.Store, token string) *Handler { return &Handler{store: s, ingestToken: token} }

// SetWebDir active le service du dashboard statique (index.html + assets) à la
// racine, servi PAR le hub. Vide = désactivé (le front est servi ailleurs).
func (h *Handler) SetWebDir(dir string) { h.webDir = dir }

// Mux enregistre les routes et retourne le multiplexeur.
func (h *Handler) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.health)
	mux.HandleFunc("GET /nodes", h.nodes)
	mux.HandleFunc("GET /graph", h.graph)
	mux.HandleFunc("GET /ego", h.ego)
	mux.HandleFunc("GET /findings", h.findings)
	mux.HandleFunc("POST /flows", h.flows)
	// Dashboard servi par le hub : "/" attrape tout ce qui n'est pas une route
	// API ci-dessus. http.FileServer sert index.html pour "/" automatiquement.
	if h.webDir != "" {
		mux.Handle("GET /", http.FileServer(http.Dir(h.webDir)))
	}
	return mux
}

// Handler retourne les routes enveloppées du CORS. C'est ce que main sert :
// le frontend (fichier HTML séparé) tape l'API depuis une autre origine.
//
// NOTE entreprise : "*" convient au dev. En prod, remplacer par la liste
// blanche des origines autorisées.
func (h *Handler) Handler() http.Handler {
	return withCORS(h.Mux())
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Ingest-Token")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// flows : POST /flows — l'agent conntrack pousse des connexions observées.
// Corps : {"flows":[{"src":"10.244.1.5","dst":"10.96.0.10"}, ...]}
func (h *Handler) flows(w http.ResponseWriter, r *http.Request) {
	if h.ingestToken != "" && r.Header.Get("X-Ingest-Token") != h.ingestToken {
		writeError(w, http.StatusUnauthorized, "token d'ingestion invalide")
		return
	}
	var body struct {
		Flows []struct {
			Src string `json:"src"`
			Dst string `json:"dst"`
		} `json:"flows"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "JSON invalide")
		return
	}
	added := 0
	for _, f := range body.Flows {
		if h.store.AddFlow(f.Src, f.Dst) {
			added++
		}
	}
	writeJSON(w, http.StatusOK, map[string]int{"received": len(body.Flows), "new_edges": added})
}

func (h *Handler) health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// nodes : GET /nodes — liste tous les nœuds (pour choisir un point de départ).
func (h *Handler) nodes(w http.ResponseWriter, _ *http.Request) {
	src := h.store.Nodes()
	out := make([]listNodeDTO, 0, len(src))
	for _, n := range src {
		out = append(out, listNodeDTO{
			ID:         idStr(n.ID),
			Cluster:    n.ID.ClusterID,
			Kind:       n.Kind,
			Namespace:  n.Namespace,
			Name:       n.Name,
			Layer:      string(n.Layer),
			NoSelector: n.NoSelector,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// graph : GET /graph — tout le graphe (nœuds + arêtes) d'un coup.
// Sert à construire des vues globales côté client (ex : Sankey de dépendances).
func (h *Handler) graph(w http.ResponseWriter, _ *http.Request) {
	srcNodes := h.store.Nodes()
	srcEdges := h.store.Edges()

	out := graphDTO{
		Nodes: make([]listNodeDTO, 0, len(srcNodes)),
		Edges: make([]edgeDTO, 0, len(srcEdges)),
	}
	for _, n := range srcNodes {
		out.Nodes = append(out.Nodes, listNodeDTO{
			ID: idStr(n.ID), Cluster: n.ID.ClusterID, Kind: n.Kind,
			Namespace: n.Namespace, Name: n.Name, Layer: string(n.Layer), NoSelector: n.NoSelector,
		})
	}
	for _, e := range srcEdges {
		out.Edges = append(out.Edges, edgeDTO{Source: idStr(e.From), Target: idStr(e.To), Type: string(e.Type)})
	}
	writeJSON(w, http.StatusOK, out)
}

// findings : GET /findings — les points d'attention sécurité (structurels).
func (h *Handler) findings(w http.ResponseWriter, _ *http.Request) {
	src := h.store.Findings()
	out := make([]findingDTO, 0, len(src))
	for _, f := range src {
		d := findingDTO{
			ID: f.ID, Severity: string(f.Severity), Category: f.Category,
			Title: f.Title, Why: f.Why, Ref: f.Ref, Node: idStr(f.Node),
		}
		if f.Peer != nil {
			d.Peer = idStr(*f.Peer)
		}
		out = append(out, d)
	}
	writeJSON(w, http.StatusOK, out)
}

// ego : GET /ego?cluster=<id>&uid=<uid>&depth=<n>
func (h *Handler) ego(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cluster := q.Get("cluster")
	uid := q.Get("uid")
	if cluster == "" || uid == "" {
		writeError(w, http.StatusBadRequest, "paramètres 'cluster' et 'uid' requis")
		return
	}

	depth := 1
	if raw := q.Get("depth"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "'depth' doit être un entier >= 0")
			return
		}
		depth = n
	}
	if depth > maxDepth {
		depth = maxDepth
	}

	sg, ok := h.store.Ego(graph.NodeID{ClusterID: cluster, UID: uid}, depth)
	if !ok {
		writeError(w, http.StatusNotFound, "nœud introuvable")
		return
	}
	writeJSON(w, http.StatusOK, toDTO(sg))
}

// --- DTO JSON (format Cytoscape : id pour les nœuds, source/target pour les arêtes) ---

type nodeDTO struct {
	ID        string `json:"id"`
	Cluster   string `json:"cluster"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Layer     string `json:"layer"`
	Origin    string `json:"origin"`
	Degree    int    `json:"degree"`
}

type listNodeDTO struct {
	ID         string `json:"id"`
	Cluster    string `json:"cluster"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
	Layer      string `json:"layer"`
	NoSelector bool   `json:"noSelector,omitempty"`
}

type edgeDTO struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Type   string `json:"type"`
}

type egoDTO struct {
	Root  string    `json:"root"`
	Nodes []nodeDTO `json:"nodes"`
	Edges []edgeDTO `json:"edges"`
}

type graphDTO struct {
	Nodes []listNodeDTO `json:"nodes"`
	Edges []edgeDTO     `json:"edges"`
}

type findingDTO struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Title    string `json:"title"`
	Why      string `json:"why"`
	Ref      string `json:"ref"`
	Node     string `json:"node"`
	Peer     string `json:"peer,omitempty"`
}

// idStr fabrique un identifiant string stable pour le frontend.
func idStr(id graph.NodeID) string { return id.ClusterID + "/" + id.UID }

func toDTO(sg store.SubGraph) egoDTO {
	out := egoDTO{
		Root:  idStr(sg.Root),
		Nodes: make([]nodeDTO, 0, len(sg.Nodes)),
		Edges: make([]edgeDTO, 0, len(sg.Edges)),
	}
	for _, en := range sg.Nodes {
		out.Nodes = append(out.Nodes, nodeDTO{
			ID:        idStr(en.Node.ID),
			Cluster:   en.Node.ID.ClusterID,
			Kind:      en.Node.Kind,
			Namespace: en.Node.Namespace,
			Name:      en.Node.Name,
			Layer:     string(en.Node.Layer),
			Origin:    string(en.Node.Origin),
			Degree:    en.Degree,
		})
	}
	for _, e := range sg.Edges {
		out.Edges = append(out.Edges, edgeDTO{
			Source: idStr(e.From),
			Target: idStr(e.To),
			Type:   string(e.Type),
		})
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

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
	store *store.Store
}

// New construit le handler.
func New(s *store.Store) *Handler { return &Handler{store: s} }

// Mux enregistre les routes et retourne le multiplexeur.
func (h *Handler) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.health)
	mux.HandleFunc("GET /nodes", h.nodes)
	mux.HandleFunc("GET /graph", h.graph)
	mux.HandleFunc("GET /ego", h.ego)
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
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
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

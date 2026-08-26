// Package store conserve le graphe en mémoire (liste d'adjacence) et répond aux
// requêtes ego-graph : à partir d'un nœud, déplier ses voisins jusqu'à une
// profondeur donnée. Le degré retourné pour chaque nœud EST son cercle dans
// l'UI (0 = le nœud sélectionné, 1 = premier cercle, ...).
package store

import (
	"sort"

	"kubegraph/internal/graph"
)

// Store est un graphe en mémoire. Non concurrent-safe pour l'instant :
// le rafraîchissement se fera par remplacement atomique (Load) plus tard.
type Store struct {
	nodes map[graph.NodeID]graph.Node
	edges []graph.Edge
	adj   map[graph.NodeID][]graph.NodeID
}

// New crée un store vide.
func New() *Store {
	return &Store{
		nodes: make(map[graph.NodeID]graph.Node),
		adj:   make(map[graph.NodeID][]graph.NodeID),
	}
}

// Load remplit le store à partir d'un ensemble de nœuds et d'arêtes.
// L'adjacence est construite dans les DEUX sens : l'ego-graph traverse les
// relations sans se soucier de leur direction.
func (s *Store) Load(nodes []graph.Node, edges []graph.Edge) {
	for _, n := range nodes {
		s.nodes[n.ID] = n
	}
	for _, e := range edges {
		s.edges = append(s.edges, e)
		s.adj[e.From] = append(s.adj[e.From], e.To)
		s.adj[e.To] = append(s.adj[e.To], e.From)
	}
}

// EgoNode est un nœud du sous-graphe, avec son degré (= son cercle).
type EgoNode struct {
	Node   graph.Node
	Degree int
}

// SubGraph est le résultat d'une requête ego : le nœud racine, les nœuds
// atteints (avec leur cercle) et les arêtes internes au périmètre.
type SubGraph struct {
	Root  graph.NodeID
	Nodes []EgoNode
	Edges []graph.Edge
}

// Ego retourne le sous-graphe autour de root jusqu'à depth cercles.
// Le booléen est false si le nœud racine n'existe pas dans le store.
func (s *Store) Ego(root graph.NodeID, depth int) (SubGraph, bool) {
	if _, ok := s.nodes[root]; !ok {
		return SubGraph{}, false
	}

	// BFS : degree[id] = cercle où le nœud a été atteint.
	degree := map[graph.NodeID]int{root: 0}
	queue := []graph.NodeID{root}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		d := degree[cur]
		if d >= depth {
			continue
		}
		for _, nb := range s.adj[cur] {
			if _, seen := degree[nb]; seen {
				continue
			}
			// Arête pendante vers un nœud non collecté (ex : propriétaire hors
			// des 5 kinds) : on l'ignore, pas de nœud fantôme.
			if _, ok := s.nodes[nb]; !ok {
				continue
			}
			degree[nb] = d + 1
			queue = append(queue, nb)
		}
	}

	// Nœuds du périmètre, triés par cercle puis par UID (sortie déterministe).
	egoNodes := make([]EgoNode, 0, len(degree))
	for id, d := range degree {
		egoNodes = append(egoNodes, EgoNode{Node: s.nodes[id], Degree: d})
	}
	sort.Slice(egoNodes, func(i, j int) bool {
		if egoNodes[i].Degree != egoNodes[j].Degree {
			return egoNodes[i].Degree < egoNodes[j].Degree
		}
		return egoNodes[i].Node.ID.UID < egoNodes[j].Node.ID.UID
	})

	// Arêtes dont les deux extrémités sont dans le périmètre.
	var subEdges []graph.Edge
	for _, e := range s.edges {
		_, okFrom := degree[e.From]
		_, okTo := degree[e.To]
		if okFrom && okTo {
			subEdges = append(subEdges, e)
		}
	}

	return SubGraph{Root: root, Nodes: egoNodes, Edges: subEdges}, true
}

// Len retourne le nombre de nœuds stockés.
func (s *Store) Len() int { return len(s.nodes) }

// Nodes retourne tous les nœuds, triés par kind puis nom (pour un menu stable).
func (s *Store) Nodes() []graph.Node {
	out := make([]graph.Node, 0, len(s.nodes))
	for _, n := range s.nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out
}

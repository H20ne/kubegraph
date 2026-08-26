// Package source définit le contrat que toute source de données doit remplir.
//
// C'est LA pièce d'architecture à poser en premier : le moteur de graphe ne
// connaît que cette interface. La source live (client-go), la source Git
// (GitOps) et l'agent hub-spoke l'implémenteront tous, sans jamais modifier
// le moteur de relations en aval.
package source

import (
	"context"

	"kubegraph/internal/graph"
)

// Source fournit l'état d'un cluster sous forme de nœuds et d'arêtes.
//
// Chaque Source est responsable de tagger correctement l'Origin de ce qu'elle
// produit (observed pour le live, declared pour le Git).
type Source interface {
	// ClusterID retourne l'identifiant du cluster représenté par cette source.
	// Il sert à préfixer les NodeID (voir le PIÈGE sur l'unicité des UID).
	ClusterID() string

	// Collect retourne l'ensemble courant des nœuds et arêtes.
	// Le contexte permet l'annulation et les timeouts.
	// L'implémentation ne doit renvoyer une erreur qu'en cas d'échec réel
	// de collecte (accès refusé, API injoignable...), pas pour un cluster vide.
	Collect(ctx context.Context) ([]graph.Node, []graph.Edge, error)
}

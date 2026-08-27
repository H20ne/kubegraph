// Source déclarée Terraform / Terragrunt.
//
// On NE parse PAS le HCL (fragile, sans fin). On consomme la sortie normalisée
// `terraform show -json` (état) ou `terraform show -json plan.tfplan` (plan) —
// pareil pour Terragrunt via `terragrunt show -json`. On ne retient que les
// ressources du provider Kubernetes (`kubernetes_*` et `kubernetes_manifest`)
// mappées vers le modèle de présence ; l'infra cloud (VPC, IAM, nodes) est ignorée
// ici (elle relèverait d'un plan « infra » séparé).
package declared

import (
	"encoding/json"
	"os"
	"strings"
)

// tfType2Kind : type de ressource TF (provider kubernetes) -> Kind Kubernetes.
// Les variantes versionnées (`..._v1`) sont normalisées en amont.
var tfType2Kind = map[string]string{
	"kubernetes_deployment": "Deployment", "kubernetes_stateful_set": "StatefulSet",
	"kubernetes_daemon_set": "DaemonSet", "kubernetes_job": "Job", "kubernetes_cron_job": "CronJob",
	"kubernetes_service": "Service", "kubernetes_ingress": "Ingress", "kubernetes_config_map": "ConfigMap",
	"kubernetes_network_policy": "NetworkPolicy", "kubernetes_service_account": "ServiceAccount",
	"kubernetes_role": "Role", "kubernetes_cluster_role": "ClusterRole",
	"kubernetes_role_binding": "RoleBinding", "kubernetes_cluster_role_binding": "ClusterRoleBinding",
	"kubernetes_horizontal_pod_autoscaler": "HorizontalPodAutoscaler",
	"kubernetes_pod_disruption_budget":     "PodDisruptionBudget",
	"kubernetes_persistent_volume_claim":   "PersistentVolumeClaim",
}

// Structures partielles de `terraform show -json` (on ne lit que ce qu'il faut).
type tfShow struct {
	Values        *tfStateValues `json:"values"`
	PlannedValues *tfStateValues `json:"planned_values"`
}
type tfStateValues struct {
	RootModule tfModule `json:"root_module"`
}
type tfModule struct {
	Resources    []tfResource `json:"resources"`
	ChildModules []tfModule   `json:"child_modules"`
}
type tfResource struct {
	Type   string          `json:"type"`
	Values json.RawMessage `json:"values"`
}

// LoadTerraformJSON lit un fichier `terraform show -json` et retourne les
// identités Kubernetes déclarées (kinds déclarables uniquement).
func LoadTerraformJSON(path string) ([]Ident, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc tfShow
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	root := doc.Values
	if root == nil {
		root = doc.PlannedValues // sortie de plan
	}
	if root == nil {
		return nil, nil
	}
	var out []Ident
	var walk func(m tfModule)
	walk = func(m tfModule) {
		for _, r := range m.Resources {
			if id, ok := tfResourceIdent(r); ok {
				out = append(out, id)
			}
		}
		for _, c := range m.ChildModules {
			walk(c)
		}
	}
	walk(root.RootModule)
	return out, nil
}

// tfResourceIdent mappe une ressource TF en Ident si c'est un objet K8s déclarable.
func tfResourceIdent(r tfResource) (Ident, bool) {
	// kubernetes_manifest : objet générique, kind/metadata dans values.manifest.
	if r.Type == "kubernetes_manifest" {
		var v struct {
			Manifest struct {
				Kind     string `json:"kind"`
				Metadata struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"metadata"`
			} `json:"manifest"`
		}
		if err := json.Unmarshal(r.Values, &v); err != nil {
			return Ident{}, false
		}
		k := v.Manifest.Kind
		if !declarable[k] || v.Manifest.Metadata.Name == "" {
			return Ident{}, false
		}
		return Ident{Kind: k, Namespace: v.Manifest.Metadata.Namespace, Name: v.Manifest.Metadata.Name}, true
	}
	// Ressources kubernetes_* typées : normalise le suffixe de version puis mappe.
	t := strings.TrimSuffix(strings.TrimSuffix(r.Type, "_v1"), "_v2")
	kind, ok := tfType2Kind[t]
	if !ok {
		return Ident{}, false
	}
	// Le provider kubernetes expose metadata comme un bloc-liste : metadata[0].
	var v struct {
		Metadata []struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(r.Values, &v); err != nil || len(v.Metadata) == 0 || v.Metadata[0].Name == "" {
		return Ident{}, false
	}
	return Ident{Kind: kind, Namespace: v.Metadata[0].Namespace, Name: v.Metadata[0].Name}, true
}

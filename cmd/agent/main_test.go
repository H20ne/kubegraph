package main

import (
	"os"
	"testing"
)

func TestReadConntrack(t *testing.T) {
	content := "" +
		"ipv4 2 tcp 6 431999 ESTABLISHED src=10.244.1.5 dst=10.96.0.10 sport=54321 dport=53 src=10.244.2.7 dst=10.244.1.5 sport=53 dport=54321 [ASSURED] mark=0 use=1\n" +
		"ipv4 2 tcp 6 60 SYN_SENT src=127.0.0.1 dst=127.0.0.1 sport=1 dport=2 [UNREPLIED] src=127.0.0.1 dst=127.0.0.1 sport=2 dport=1 mark=0 use=1\n"

	f, err := os.CreateTemp(t.TempDir(), "ct")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()

	flows, err := readConntrack(f.Name())
	if err != nil {
		t.Fatalf("readConntrack : %v", err)
	}
	got := map[string]bool{}
	for _, fl := range flows {
		got[fl.Src+"->"+fl.Dst] = true
	}
	// tuple original (vers le ClusterIP) et src du tuple réponse (le pod réel)
	if !got["10.244.1.5->10.96.0.10"] {
		t.Error("flux original client->ClusterIP manquant")
	}
	if !got["10.244.1.5->10.244.2.7"] {
		t.Error("flux client->pod réel (reply) manquant")
	}
	// la ligne loopback doit être entièrement écartée
	if len(flows) != 2 {
		t.Errorf("attendu 2 flux, obtenu %d : %v", len(flows), flows)
	}
}

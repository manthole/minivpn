package main

import (
	"testing"

	"github.com/manthole/minivpn/internal/vpn"
)

func TestPeerFlag(t *testing.T) {
	priv, _ := vpn.GeneratePrivateKey()
	pub, _ := priv.Public()
	var l peerList
	// une clé Base64 se termine par « = » : le séparateur est le dernier signe égal
	if err := l.Set(pub.String() + "=10.8.0.2"); err != nil {
		t.Fatal(err)
	}
	if len(l) != 1 || l[0].PublicKey != pub || l[0].Address.String() != "10.8.0.2" {
		t.Fatalf("lecture incorrecte : %+v", l)
	}
	for _, bad := range []string{"", "=10.8.0.2", pub.String(), pub.String() + "=pas-une-ip", "abc=10.8.0.2"} {
		if err := l.Set(bad); err == nil {
			t.Errorf("%q accepté à tort", bad)
		}
	}
}

package vpn

// Tests de bout en bout du protocole : un vrai serveur et de vrais clients échangent en
// UDP sur 127.0.0.1. Seule l'interface TUN est simulée (canaux Go), ce qui permet de
// lancer ces tests sans droits administrateur.

import (
	"bytes"
	"context"
	"encoding/binary"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- interface simulée ---------------------------------------------------------------

type chanDev struct {
	in   chan []byte // paquets « émis par le système » que le nœud va lire
	out  chan []byte // paquets que le nœud « livre au système »
	done chan struct{}
	once sync.Once
}

func newChanDev() *chanDev {
	return &chanDev{in: make(chan []byte, 256), out: make(chan []byte, 256), done: make(chan struct{})}
}

func (d *chanDev) Read(p []byte) (int, error) {
	select {
	case pkt := <-d.in:
		return copy(p, pkt), nil
	case <-d.done:
		return 0, os.ErrClosed
	}
}

func (d *chanDev) Write(p []byte) (int, error) {
	select {
	case d.out <- append([]byte(nil), p...):
		return len(p), nil
	case <-d.done:
		return 0, os.ErrClosed
	}
}

func (d *chanDev) Close() error { d.once.Do(func() { close(d.done) }); return nil }

// --- socket UDP qui enregistre ce qu'elle envoie ----------------------------------------

type tapConn struct {
	*net.UDPConn
	mu   sync.Mutex
	sent [][]byte
}

func (c *tapConn) WriteToUDPAddrPort(b []byte, a netip.AddrPort) (int, error) {
	c.mu.Lock()
	c.sent = append(c.sent, append([]byte(nil), b...))
	c.mu.Unlock()
	return c.UDPConn.WriteToUDPAddrPort(b, a)
}

func (c *tapConn) sentOfType(typ byte, minLen int) [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out [][]byte
	for _, b := range c.sent {
		if b[0] == typ && len(b) >= minLen {
			out = append(out, b)
		}
	}
	return out
}

func (c *tapConn) addr() netip.AddrPort { return c.LocalAddr().(*net.UDPAddr).AddrPort() }

func listenLocal(t *testing.T) *tapConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return &tapConn{UDPConn: c}
}

// --- journal partagé -------------------------------------------------------------------

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// --- outils ----------------------------------------------------------------------------

type testNode struct {
	n    *Node
	dev  *chanDev
	conn *tapConn
	logs *syncBuf
}

func newKey(t *testing.T) (priv, pub Key) {
	t.Helper()
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err = priv.Public()
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func run(t *testing.T, n *Node) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- n.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run : %v", err)
		}
	})
}

func startServer(t *testing.T, priv Key, peers []PeerConfig, tm *timing) *testNode {
	t.Helper()
	tn := &testNode{dev: newChanDev(), conn: listenLocal(t), logs: &syncBuf{}}
	n, err := NewServer(ServerConfig{PrivateKey: priv, Address: netip.MustParsePrefix("10.8.0.1/24"), Peers: peers},
		tn.conn, tn.dev, log.New(tn.logs, "serveur ", 0), true)
	if err != nil {
		t.Fatal(err)
	}
	if tm != nil {
		n.timing = *tm
	}
	tn.n = n
	run(t, n)
	return tn
}

func startClient(t *testing.T, priv Key, addr string, server netip.AddrPort, serverKey Key, tm *timing) *testNode {
	t.Helper()
	tn := &testNode{dev: newChanDev(), conn: listenLocal(t), logs: &syncBuf{}}
	n, err := NewClient(ClientConfig{PrivateKey: priv, Address: netip.MustParsePrefix(addr), Server: server, ServerKey: serverKey},
		tn.conn, tn.dev, log.New(tn.logs, "client ", 0), true)
	if err != nil {
		t.Fatal(err)
	}
	if tm != nil {
		n.timing = *tm
	}
	tn.n = n
	run(t, n)
	return tn
}

func ipv4(src, dst string, payload string) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8], pkt[9] = 64, 17
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	copy(pkt[20:], payload)
	return pkt
}

func expectPacket(t *testing.T, ch chan []byte, want []byte, what string) {
	t.Helper()
	select {
	case got := <-ch:
		if !bytes.Equal(got, want) {
			t.Fatalf("%s : paquet différent de celui attendu", what)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("%s : rien reçu", what)
	}
}

func expectNothing(t *testing.T, ch chan []byte, what string) {
	t.Helper()
	select {
	case <-ch:
		t.Fatalf("%s : un paquet a été livré alors qu'il devait être refusé", what)
	case <-time.After(400 * time.Millisecond):
	}
}

func waitLog(t *testing.T, logs *syncBuf, substr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(logs.String(), substr) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("message %q absent du journal :\n%s", substr, logs.String())
}

// sendRaw envoie un datagramme depuis une socket « attaquante » quelconque.
func sendRaw(t *testing.T, to netip.AddrPort, b []byte) {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.WriteToUDPAddrPort(b, to); err != nil {
		t.Fatal(err)
	}
}

// --- tests -----------------------------------------------------------------------------

func TestKeys(t *testing.T) {
	priv, pub := newKey(t)
	k, err := ParseKey(pub.String())
	if err != nil || k != pub {
		t.Fatalf("aller-retour Base64 raté : %v", err)
	}
	if p2, _ := priv.Public(); p2 != pub {
		t.Fatal("clé publique non déterministe")
	}
	for _, bad := range []string{"", "pas du base64 !", "AAAA"} {
		if _, err := ParseKey(bad); err == nil {
			t.Fatalf("ParseKey(%q) aurait dû échouer", bad)
		}
	}
	path := t.TempDir() + "/k"
	if err := WritePrivateKey(path, priv); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateKey(path, priv); err == nil {
		t.Fatal("une clé existante a été écrasée")
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("droits du fichier de clé : %v", info.Mode().Perm())
	}
	if k, err := LoadPrivateKey(path); err != nil || k != priv {
		t.Fatalf("relecture de la clé : %v", err)
	}
}

func TestTunnelBothWays(t *testing.T) {
	sPriv, sPub := newKey(t)
	cPriv, cPub := newKey(t)
	srv := startServer(t, sPriv, []PeerConfig{{cPub, netip.MustParseAddr("10.8.0.2")}}, nil)
	cli := startClient(t, cPriv, "10.8.0.2/24", srv.conn.addr(), sPub, nil)

	// envoyé avant la fin de la poignée de main : mis en attente puis transmis
	ping := ipv4("10.8.0.2", "10.8.0.1", "ping")
	cli.dev.in <- ping
	expectPacket(t, srv.dev.out, ping, "client → serveur")

	pong := ipv4("10.8.0.1", "10.8.0.2", "pong")
	srv.dev.in <- pong
	expectPacket(t, cli.dev.out, pong, "serveur → client")

	waitLog(t, cli.logs, "tunnel établi")
	waitLog(t, srv.logs, "client 10.8.0.2 connecté")

	// ce qui circule sur le réseau ne contient pas le texte en clair
	for _, b := range cli.conn.sentOfType(msgData, 0) {
		if bytes.Contains(b, []byte("ping")) {
			t.Fatal("le contenu circule en clair sur le réseau !")
		}
	}
}

func TestUnknownClientRejected(t *testing.T) {
	sPriv, sPub := newKey(t)
	_, allowed := newKey(t)
	intruder, _ := newKey(t)
	srv := startServer(t, sPriv, []PeerConfig{{allowed, netip.MustParseAddr("10.8.0.2")}}, nil)
	cli := startClient(t, intruder, "10.8.0.2/24", srv.conn.addr(), sPub, nil)

	cli.dev.in <- ipv4("10.8.0.2", "10.8.0.1", "je ne suis pas autorisé")
	waitLog(t, srv.logs, "refusé : clé inconnue")
	expectNothing(t, srv.dev.out, "client inconnu")
	if len(srv.conn.sentOfType(msgResponse, 0)) != 0 {
		t.Fatal("le serveur a répondu à un client inconnu")
	}
}

func TestWrongServerKey(t *testing.T) {
	sPriv, _ := newKey(t)
	_, wrong := newKey(t)
	cPriv, cPub := newKey(t)
	srv := startServer(t, sPriv, []PeerConfig{{cPub, netip.MustParseAddr("10.8.0.2")}}, nil)
	cli := startClient(t, cPriv, "10.8.0.2/24", srv.conn.addr(), wrong, nil)

	cli.dev.in <- ipv4("10.8.0.2", "10.8.0.1", "x")
	waitLog(t, srv.logs, "poignée de main illisible")
	expectNothing(t, srv.dev.out, "mauvaise clé serveur")
}

func TestReplayedHandshakeRejected(t *testing.T) {
	sPriv, sPub := newKey(t)
	cPriv, cPub := newKey(t)
	srv := startServer(t, sPriv, []PeerConfig{{cPub, netip.MustParseAddr("10.8.0.2")}}, nil)
	cli := startClient(t, cPriv, "10.8.0.2/24", srv.conn.addr(), sPub, nil)
	waitLog(t, srv.logs, "client 10.8.0.2 connecté")

	inits := cli.conn.sentOfType(msgInit, 0)
	responses := len(srv.conn.sentOfType(msgResponse, 0))
	sendRaw(t, srv.conn.addr(), inits[0]) // un attaquant rejoue la poignée de main capturée
	waitLog(t, srv.logs, "rejouée ou périmée")
	time.Sleep(100 * time.Millisecond)
	if len(srv.conn.sentOfType(msgResponse, 0)) != responses {
		t.Fatal("le serveur a répondu à une poignée de main rejouée")
	}
}

// Après un redémarrage, le serveur a oublié les horodatages : une vieille poignée de main
// capturée redevient acceptable une fois. Elle ne doit pas détourner le trafic du client.
func TestReplayAfterServerRestartCannotHijack(t *testing.T) {
	sPriv, sPub := newKey(t)
	cPriv, cPub := newKey(t)
	srv := startServer(t, sPriv, []PeerConfig{{cPub, netip.MustParseAddr("10.8.0.2")}}, nil)
	cli := startClient(t, cPriv, "10.8.0.2/24", srv.conn.addr(), sPub, nil)
	waitLog(t, srv.logs, "client 10.8.0.2 connecté")

	srv.n.mu.Lock()
	srv.n.peers[cPub].lastInit = [timestampLen]byte{} // simule la perte de mémoire
	srv.n.mu.Unlock()
	responses := len(srv.conn.sentOfType(msgResponse, 0))
	sendRaw(t, srv.conn.addr(), cli.conn.sentOfType(msgInit, 0)[0])
	deadline := time.Now().Add(2 * time.Second)
	for len(srv.conn.sentOfType(msgResponse, 0)) == responses && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	pkt := ipv4("10.8.0.1", "10.8.0.2", "toujours pour le vrai client")
	srv.dev.in <- pkt
	expectPacket(t, cli.dev.out, pkt, "trafic après la poignée de main rejouée")
}

func TestReplayedAndTamperedDataRejected(t *testing.T) {
	sPriv, sPub := newKey(t)
	cPriv, cPub := newKey(t)
	srv := startServer(t, sPriv, []PeerConfig{{cPub, netip.MustParseAddr("10.8.0.2")}}, nil)
	cli := startClient(t, cPriv, "10.8.0.2/24", srv.conn.addr(), sPub, nil)

	pkt := ipv4("10.8.0.2", "10.8.0.1", "virement de 10 euros")
	cli.dev.in <- pkt
	expectPacket(t, srv.dev.out, pkt, "paquet légitime")

	captured := cli.conn.sentOfType(msgData, dataHeaderLen+tagLen+1)[0]
	sendRaw(t, srv.conn.addr(), captured)
	expectNothing(t, srv.dev.out, "paquet rejoué")

	tampered := append([]byte(nil), captured...)
	tampered[len(tampered)-20] ^= 0x01 // un seul bit modifié dans le chiffré
	sendRaw(t, srv.conn.addr(), tampered)
	expectNothing(t, srv.dev.out, "paquet altéré")

	header := append([]byte(nil), captured...)
	header[8] ^= 0x01 // compteur modifié (en-tête authentifié)
	sendRaw(t, srv.conn.addr(), header)
	expectNothing(t, srv.dev.out, "en-tête altéré")

	// le tunnel fonctionne toujours, et l'adresse du client n'a pas été détournée
	pkt2 := ipv4("10.8.0.2", "10.8.0.1", "toujours là")
	cli.dev.in <- pkt2
	expectPacket(t, srv.dev.out, pkt2, "après les attaques")
	reply := ipv4("10.8.0.1", "10.8.0.2", "réponse")
	srv.dev.in <- reply
	expectPacket(t, cli.dev.out, reply, "réponse au vrai client")
}

func TestSpoofedSourceRejected(t *testing.T) {
	sPriv, sPub := newKey(t)
	cPriv, cPub := newKey(t)
	srv := startServer(t, sPriv, []PeerConfig{{cPub, netip.MustParseAddr("10.8.0.2")}}, nil)
	cli := startClient(t, cPriv, "10.8.0.2/24", srv.conn.addr(), sPub, nil)

	// le client authentifié tente de se faire passer pour 10.8.0.99
	cli.dev.in <- ipv4("10.8.0.99", "10.8.0.1", "usurpation")
	waitLog(t, srv.logs, "adresse source usurpée")
	expectNothing(t, srv.dev.out, "source usurpée")
}

func TestClientToClientRelay(t *testing.T) {
	sPriv, sPub := newKey(t)
	aPriv, aPub := newKey(t)
	bPriv, bPub := newKey(t)
	srv := startServer(t, sPriv, []PeerConfig{
		{aPub, netip.MustParseAddr("10.8.0.2")},
		{bPub, netip.MustParseAddr("10.8.0.3")},
	}, nil)
	a := startClient(t, aPriv, "10.8.0.2/24", srv.conn.addr(), sPub, nil)
	b := startClient(t, bPriv, "10.8.0.3/24", srv.conn.addr(), sPub, nil)
	waitLog(t, srv.logs, "client 10.8.0.3 connecté")

	msg := ipv4("10.8.0.2", "10.8.0.3", "bonjour B")
	a.dev.in <- msg
	expectPacket(t, b.dev.out, msg, "A → B via le serveur")
	expectNothing(t, srv.dev.out, "le relais ne doit pas passer par le système du serveur")
}

func TestRekeyKeepsTrafficFlowing(t *testing.T) {
	fast := &timing{
		tick:              10 * time.Millisecond,
		rekeyAfterTime:    300 * time.Millisecond,
		rejectAfterTime:   900 * time.Millisecond,
		rekeyTimeout:      200 * time.Millisecond,
		keepaliveInterval: 100 * time.Millisecond,
	}
	sPriv, sPub := newKey(t)
	cPriv, cPub := newKey(t)
	srv := startServer(t, sPriv, []PeerConfig{{cPub, netip.MustParseAddr("10.8.0.2")}}, fast)
	cli := startClient(t, cPriv, "10.8.0.2/24", srv.conn.addr(), sPub, fast)

	for i := 0; i < 40; i++ {
		up := ipv4("10.8.0.2", "10.8.0.1", "montant "+string(rune('A'+i%26)))
		cli.dev.in <- up
		expectPacket(t, srv.dev.out, up, "client → serveur pendant les renouvellements")
		down := ipv4("10.8.0.1", "10.8.0.2", "descendant")
		srv.dev.in <- down
		expectPacket(t, cli.dev.out, down, "serveur → client pendant les renouvellements")
		time.Sleep(50 * time.Millisecond)
	}
	if n := len(cli.conn.sentOfType(msgInit, 0)); n < 4 {
		t.Fatalf("seulement %d poignées de main en 2 s : les clés n'ont pas été renouvelées", n)
	}
	// aucune session expirée ne doit rester en mémoire
	srv.n.mu.Lock()
	defer srv.n.mu.Unlock()
	if len(srv.n.sessions) > 3 {
		t.Fatalf("%d sessions encore en mémoire côté serveur", len(srv.n.sessions))
	}
}

func TestServerConfigValidation(t *testing.T) {
	sPriv, sPub := newKey(t)
	_, c := newKey(t)
	cases := map[string][]PeerConfig{
		"aucun client":       nil,
		"hors du réseau":     {{c, netip.MustParseAddr("10.9.0.2")}},
		"adresse du serveur": {{c, netip.MustParseAddr("10.8.0.1")}},
		"clé du serveur":     {{sPub, netip.MustParseAddr("10.8.0.2")}},
		"clé en double":      {{c, netip.MustParseAddr("10.8.0.2")}, {c, netip.MustParseAddr("10.8.0.3")}},
	}
	for name, peers := range cases {
		_, err := NewServer(ServerConfig{PrivateKey: sPriv, Address: netip.MustParsePrefix("10.8.0.1/24"), Peers: peers}, nil, nil, nil, false)
		if err == nil {
			t.Errorf("%s : configuration acceptée à tort", name)
		}
	}
}

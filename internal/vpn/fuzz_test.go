package vpn

// Fuzzing : le serveur reçoit des paquets de n'importe qui sur Internet. Le fuzzer de Go
// (go test -fuzz) leur envoie des millions de variantes abîmées et vérifie, pour chacune :
//
//   - aucun plantage (lecture hors limites, index négatif, division par zéro…) ;
//   - aucune amplification : jamais plus d'octets renvoyés que d'octets reçus ;
//   - rien n'arrive sur l'interface réseau sans être authentique, et jamais deux fois ;
//   - un paquet forgé ne change ni l'adresse du client ni l'état des sessions.
//
// Sans -fuzz, « go test » rejoue seulement les entrées de départ et celles du dossier
// testdata/fuzz : ce sont alors des tests de non-régression ordinaires.
//
//	go test -run '^$' -fuzz '^FuzzServerPacket$' -fuzztime 60s ./internal/vpn/
//
// L'aléa des nœuds (clés éphémères, index) est figé par une graine : la même entrée rejoue
// exactement la même poignée de main, donc un échec trouvé par le fuzzer se reproduit.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// detReader : flux pseudo-aléatoire déterministe (SHA-256 en mode compteur).
type detReader struct {
	seed [32]byte
	ctr  uint64
	buf  []byte
}

func newDetReader(label string) *detReader { return &detReader{seed: sha256.Sum256([]byte(label))} }

func (r *detReader) Read(p []byte) (int, error) {
	for i := range p {
		if len(r.buf) == 0 {
			var b [40]byte
			copy(b[:], r.seed[:])
			binary.LittleEndian.PutUint64(b[32:], r.ctr)
			r.ctr++
			h := sha256.Sum256(b[:])
			r.buf = h[:]
		}
		p[i] = r.buf[0]
		r.buf = r.buf[1:]
	}
	return len(p), nil
}

// captureConn et captureDev retiennent ce qui est envoyé, sans réseau ni interface réelle.
type captureConn struct {
	out [][]byte
	to  []netip.AddrPort
}

func (c *captureConn) ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error) {
	panic("non utilisé par le fuzzing")
}
func (c *captureConn) WriteToUDPAddrPort(b []byte, a netip.AddrPort) (int, error) {
	c.out = append(c.out, append([]byte(nil), b...))
	c.to = append(c.to, a)
	return len(b), nil
}
func (c *captureConn) Close() error { return nil }
func (c *captureConn) last() []byte { return c.out[len(c.out)-1] }
func (c *captureConn) bytesSince(i int) (n int) {
	for _, b := range c.out[i:] {
		n += len(b)
	}
	return n
}

type captureDev struct{ out [][]byte }

func (d *captureDev) Read([]byte) (int, error) { panic("non utilisé par le fuzzing") }
func (d *captureDev) Write(p []byte) (int, error) {
	d.out = append(d.out, append([]byte(nil), p...))
	return len(p), nil
}
func (d *captureDev) Close() error { return nil }

var (
	fuzzClock   = time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	fuzzServer  = netip.MustParseAddrPort("203.0.113.1:51820")
	fuzzClient  = netip.MustParseAddrPort("198.51.100.7:40000")
	fuzzSrvPriv = Key(sha256.Sum256([]byte("minivpn fuzz : serveur")))
	fuzzCliPriv = Key(sha256.Sum256([]byte("minivpn fuzz : client")))
	fuzzC2Priv  = Key(sha256.Sum256([]byte("minivpn fuzz : second client")))
)

// fuzzWorld : un serveur et un client réels, reliés à la main, sans goroutine.
type fuzzWorld struct {
	srv, cli         *Node
	srvConn, cliConn *captureConn
	srvDev, cliDev   *captureDev
	init, resp       []byte   // poignée de main authentique
	keepalive        []byte   // premier paquet de données du client (session confirmée)
	data             [][]byte // paquets de données authentiques client → serveur
	plain            [][]byte // leur contenu en clair
}

func mustPublic(t testing.TB, k Key) Key {
	pub, err := k.Public()
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// newFuzzWorld prépare le décor. stage : 1 = poignée de main envoyée par le client
// (en attente), 2 = tunnel établi et confirmé, avec des paquets de données authentiques.
func newFuzzWorld(t testing.TB, stage int) *fuzzWorld {
	w := &fuzzWorld{srvConn: &captureConn{}, cliConn: &captureConn{}, srvDev: &captureDev{}, cliDev: &captureDev{}}
	srvPub, cliPub, c2Pub := mustPublic(t, fuzzSrvPriv), mustPublic(t, fuzzCliPriv), mustPublic(t, fuzzC2Priv)
	var err error
	w.srv, err = NewServer(ServerConfig{PrivateKey: fuzzSrvPriv, Address: netip.MustParsePrefix("10.8.0.1/24"),
		Peers: []PeerConfig{{cliPub, netip.MustParseAddr("10.8.0.2")}, {c2Pub, netip.MustParseAddr("10.8.0.3")}}},
		w.srvConn, w.srvDev, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	w.cli, err = NewClient(ClientConfig{PrivateKey: fuzzCliPriv, Address: netip.MustParsePrefix("10.8.0.2/24"),
		Server: fuzzServer, ServerKey: srvPub}, w.cliConn, w.cliDev, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []*Node{w.srv, w.cli} {
		n.now = func() time.Time { return fuzzClock }
	}
	w.srv.random, w.cli.random = newDetReader("serveur"), newDetReader("client")
	w.srv.cookies = newCookieJar(w.srv.keys, w.srv.random)

	w.cli.initiate(w.cli.upstream)
	w.init = w.cliConn.last()
	if stage < 2 {
		return w
	}
	w.srv.handlePacket(w.init, fuzzClient)
	w.resp = w.srvConn.last()
	w.cli.handlePacket(w.resp, fuzzServer)
	w.keepalive = w.cliConn.last()
	w.srv.handlePacket(w.keepalive, fuzzClient)
	if p := w.srv.byIP[netip.MustParseAddr("10.8.0.2")]; p.current == nil || !p.current.confirmed {
		t.Fatal("décor : tunnel non établi")
	}
	for _, pkt := range [][]byte{
		ipv4("10.8.0.2", "10.8.0.1", "vers le serveur"),
		ipv4("10.8.0.2", "10.8.0.3", "vers l'autre client (relais)"),
		ipv4("10.8.0.9", "10.8.0.1", "source usurpée"),
		ipv4("10.8.0.2", "10.8.0.1", strings.Repeat("x", 1300)),
	} {
		w.cli.sendPacket(w.cli.upstream, pkt)
		w.data = append(w.data, w.cliConn.last())
		w.plain = append(w.plain, pkt)
	}
	w.srvConn.out, w.srvConn.to, w.srvDev.out = nil, nil, nil
	return w
}

func FuzzServerPacket(f *testing.F) {
	w := newFuzzWorld(f, 2)
	for _, pkt := range append([][]byte{w.init, w.resp, w.keepalive}, w.data...) {
		f.Add(pkt, uint16(fuzzClient.Port()), false)
		f.Add(pkt, uint16(fuzzClient.Port()), true)
	}
	f.Add(forgedInit(mustPublic(f, fuzzSrvPriv)), uint16(1), true)
	f.Add([]byte{msgCookie, 0, 0, 0}, uint16(2), false)
	f.Add(make([]byte, dataHeaderLen+tagLen), uint16(3), false)

	f.Fuzz(func(t *testing.T, pkt []byte, port uint16, load bool) {
		w := newFuzzWorld(t, 2)
		authentic := -1
		for i, d := range w.data {
			if bytes.Equal(pkt, d) {
				authentic = i
			}
		}
		if bytes.Equal(pkt, w.keepalive) {
			authentic = len(w.data) // authentique, mais déjà reçu : doit être refusé
		}
		if load {
			w.srv.cookies.load = rateLimiter{rate: 0.5}
		}
		from := netip.AddrPortFrom(fuzzClient.Addr(), port)
		p := w.srv.byIP[netip.MustParseAddr("10.8.0.2")]
		current := p.current
		in := append([]byte(nil), pkt...)

		for round := 0; round < 2; round++ { // le même paquet deux fois : le second est un rejeu
			sent := len(w.srvConn.out)
			w.srv.handlePacket(pkt, from)
			if !bytes.Equal(pkt, in) {
				t.Fatal("le serveur a modifié le paquet reçu")
			}
			if n := w.srvConn.bytesSince(sent); n > len(pkt) {
				t.Fatalf("amplification : %d octets reçus, %d renvoyés", len(pkt), n)
			}
		}

		// Livraison sur l'interface : seulement un paquet authentique, une seule fois, intact.
		switch {
		case authentic < 0 || authentic == len(w.data):
			if len(w.srvDev.out) != 0 {
				t.Fatalf("paquet non authentique (ou rejoué) livré sur l'interface : %x", w.srvDev.out[0])
			}
		case authentic == 0 || authentic == 3:
			if len(w.srvDev.out) != 1 || !bytes.Equal(w.srvDev.out[0], w.plain[authentic]) {
				t.Fatalf("paquet authentique livré %d fois (attendu : une fois, intact)", len(w.srvDev.out))
			}
		default: // relais vers un client sans session, source usurpée : rien sur l'interface
			if len(w.srvDev.out) != 0 {
				t.Fatal("paquet relayé ou usurpé livré sur l'interface du serveur")
			}
		}
		// Un paquet forgé ne déplace pas le client et ne remplace pas sa session.
		if authentic < 0 && p.endpoint != fuzzClient {
			t.Fatalf("adresse du client détournée vers %s par un paquet forgé", p.endpoint)
		}
		if p.current != current {
			t.Fatal("session courante remplacée par un paquet reçu")
		}
	})
}

func FuzzClientPacket(f *testing.F) {
	// Réponse et cookie authentiques pour la poignée de main en attente : comme l'aléa est
	// figé, chaque nouveau décor envoie exactement la même poignée de main.
	w0 := newFuzzWorld(f, 2)
	loaded := newFuzzWorld(f, 1)
	loaded.srv.cookies.load = rateLimiter{rate: 0.5}
	loaded.srv.handlePacket(loaded.init, fuzzClient)
	loaded.srv.handlePacket(loaded.init, fuzzClient)
	cookie := loaded.srvConn.last()
	if len(cookie) != cookieLen || cookie[0] != msgCookie {
		f.Fatal("décor : pas de message cookie")
	}
	for _, pkt := range [][]byte{w0.resp, cookie, w0.keepalive, w0.init, w0.data[0]} {
		f.Add(pkt)
	}

	f.Fuzz(func(t *testing.T, pkt []byte) {
		w := newFuzzWorld(t, 1)
		p := w.cli.upstream
		w.cliConn.out = nil
		w.cli.handlePacket(pkt, fuzzServer)
		if len(w.cliDev.out) != 0 {
			t.Fatal("paquet livré sur l'interface sans tunnel établi")
		}
		// mac2 (16 derniers octets) n'est pas authentifié et le client ne le lit pas : comme
		// dans WireGuard, il ne sert qu'au destinataire sous charge. Le fuzzer l'a rappelé
		// en modifiant ces octets d'une réponse authentique, toujours acceptée.
		if len(pkt) == respLen && bytes.Equal(pkt[:respLen-macLen], w0.resp[:respLen-macLen]) {
			if p.current == nil || len(w.cliConn.out) != 1 {
				t.Fatal("réponse authentique refusée")
			}
			return
		}
		if p.current != nil {
			t.Fatal("tunnel établi par un message qui n'est pas la réponse du serveur")
		}
		if len(w.cliConn.out) != 0 {
			t.Fatalf("le client a répondu à un message forgé (%d paquets)", len(w.cliConn.out))
		}
		if p.cookie.value != ([macLen]byte{}) && !bytes.Equal(pkt, cookie) {
			t.Fatal("cookie forgé accepté")
		}
	})
}

// FuzzReplayFilter compare le filtre (fenêtre circulaire de la RFC 6479) à un modèle
// naïf : un ensemble de tous les compteurs vus, et la même règle d'âge.
func FuzzReplayFilter(f *testing.F) {
	f.Add([]byte{1, 0, 1, 0, 2, 0, 1, 0})
	f.Add([]byte{0, 0xff, 0x7f, 1, 0, 0x80, 2, 0x10, 0, 0, 0, 0, 0, 0, 0x10})
	f.Fuzz(func(t *testing.T, ops []byte) {
		var filter replayFilter
		seen := map[uint64]bool{}
		var last uint64
		for len(ops) >= 3 {
			var c uint64
			switch op := ops[0] % 4; {
			case op == 0 && len(ops) >= 9: // compteur arbitraire
				c = binary.LittleEndian.Uint64(ops[1:9])
				ops = ops[9:]
			default: // près du maximum, devant ou derrière (désordre, pertes, rejeux)
				delta := int64(int16(binary.LittleEndian.Uint16(ops[1:3])))
				if int64(last)+delta < 0 {
					c = 0
				} else {
					c = uint64(int64(last) + delta)
				}
				ops = ops[3:]
			}
			want := c < rejectAfterMessages && !seen[c] && (c > last || last-c <= replayWindow)
			if got := filter.accept(c); got != want {
				t.Fatalf("compteur %d (maximum %d) : filtre %v, modèle %v", c, last, got, want)
			}
			if want {
				seen[c] = true
				if c > last {
					last = c
				}
			}
		}
	})
}

func FuzzParseKey(f *testing.F) {
	for _, s := range []string{fuzzSrvPriv.String(), " " + fuzzCliPriv.String() + "\n", "", "====",
		strings.Repeat("A", 43) + "B", strings.Repeat("A", 44), "AAAA\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		k, err := ParseKey(s)
		if err != nil {
			return
		}
		again, err := ParseKey(k.String())
		if err != nil || again != k {
			t.Fatalf("clé %q relue différemment", s)
		}
		if _, err := k.Public(); err != nil {
			t.Fatalf("clé %q acceptée mais inutilisable : %v", s, err)
		}
	})
}

func FuzzParseIPv4(f *testing.F) {
	f.Add(ipv4("10.8.0.2", "10.8.0.1", "ok"))
	f.Add([]byte{0x4f, 0, 0, 0x3c})
	f.Add(make([]byte, 20))
	f.Fuzz(func(t *testing.T, pkt []byte) {
		src, dst, ok := parseIPv4(pkt)
		if !ok {
			return
		}
		ihl := int(pkt[0]&0x0f) * 4
		if len(pkt) < ihl || ihl < 20 || pkt[0]>>4 != 4 || !src.Is4() || !dst.Is4() {
			t.Fatalf("paquet invalide accepté : %x", pkt)
		}
	})
}

package vpn

// Tests du mécanisme anti-déni de service : mac1, cookies sous charge, limite par adresse.

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var fastRetry = &timing{
	tick:              10 * time.Millisecond,
	rekeyAfterTime:    120 * time.Second,
	rejectAfterTime:   180 * time.Second,
	rekeyTimeout:      150 * time.Millisecond,
	keepaliveInterval: 10 * time.Second,
}

// forceLoad met le serveur sous charge dès la première poignée de main.
func forceLoad(srv *testNode) {
	srv.n.mu.Lock()
	srv.n.cookies.load = rateLimiter{rate: 0.5}
	srv.n.mu.Unlock()
}

// forgedInit fabrique une poignée de main bidon mais au mac1 valide : il suffit de
// connaître la clé publique du serveur (elle n'est pas secrète). mac2 reste à zéro.
func forgedInit(serverPub Key) []byte {
	msg := make([]byte, initLen-macsLen)
	msg[0] = msgInit
	rand.Read(msg[4:])
	out, _ := appendMACs(msg, deriveMACKeys(serverPub), nil, time.Now())
	return out
}

func countLogs(logs *syncBuf, substr string) int { return strings.Count(logs.String(), substr) }

func TestMessageSizesMatchWireGuard(t *testing.T) {
	if initLen != 148 || respLen != 92 || cookieLen != 64 {
		t.Fatalf("tailles : init %d, réponse %d, cookie %d (WireGuard : 148, 92, 64)", initLen, respLen, cookieLen)
	}
}

func TestForgedHandshakeRejectedBeforeAnyDH(t *testing.T) {
	sPriv, _ := newKey(t)
	_, cPub := newKey(t)
	srv := startServer(t, sPriv, []PeerConfig{{cPub, netip.MustParseAddr("10.8.0.2")}}, nil)

	junk := make([]byte, initLen)
	junk[0] = msgInit
	rand.Read(junk[4:])
	sendRaw(t, srv.conn.addr(), junk)
	waitLog(t, srv.logs, "mac1 invalide")
	if strings.Contains(srv.logs.String(), "poignée de main illisible") {
		t.Fatal("un message au mac1 invalide a atteint le déchiffrement Noise")
	}
	if len(srv.conn.sent) != 0 {
		t.Fatal("le serveur a répondu à un message forgé")
	}
}

func TestCookieLetsClientInUnderLoad(t *testing.T) {
	sPriv, sPub := newKey(t)
	cPriv, cPub := newKey(t)
	srv := startServer(t, sPriv, []PeerConfig{{cPub, netip.MustParseAddr("10.8.0.2")}}, fastRetry)
	forceLoad(srv)
	cli := startClient(t, cPriv, "10.8.0.2/24", srv.conn.addr(), sPub, fastRetry)

	ping := ipv4("10.8.0.2", "10.8.0.1", "sous charge")
	cli.dev.in <- ping
	expectPacket(t, srv.dev.out, ping, "client avec cookie")
	waitLog(t, srv.logs, "sous charge")
	waitLog(t, cli.logs, "cookie reçu")
	if len(srv.conn.sentOfType(msgCookie, cookieLen)) == 0 {
		t.Fatal("aucun cookie envoyé alors que le serveur est sous charge")
	}
	// la poignée de main acceptée porte un mac2 non nul
	inits := cli.conn.sentOfType(msgInit, initLen)
	last := inits[len(inits)-1]
	if bytes.Equal(last[initLen-macLen:], make([]byte, macLen)) {
		t.Fatal("la poignée de main acceptée n'a pas de mac2")
	}
}

// Le cas pour lequel le mécanisme existe : un flot de poignées de main forgées, venant
// d'adresses usurpées (l'attaquant ne lit jamais les réponses), ne doit ni faire calculer
// le serveur ni empêcher un vrai client de se connecter. Avant, une limite globale de 100
// par seconde faisait faire au serveur 100 calculs Diffie-Hellman par seconde pour
// l'attaquant, et le vrai client tirait au sort sa place parmi les faux messages.
func TestFloodOfSpoofedHandshakesDoesNotLockOutClient(t *testing.T) {
	sPriv, sPub := newKey(t)
	cPriv, cPub := newKey(t)
	srv := startServer(t, sPriv, []PeerConfig{{cPub, netip.MustParseAddr("10.8.0.2")}}, fastRetry)

	attacker, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer attacker.Close()
	var stop atomic.Bool
	var sent atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for !stop.Load() {
			for i := 0; i < 50; i++ {
				attacker.WriteToUDPAddrPort(forgedInit(sPub), srv.conn.addr())
				sent.Add(1)
			}
			time.Sleep(5 * time.Millisecond) // environ 10 000 messages par seconde
		}
	}()
	defer func() {
		if !stop.Swap(true) {
			<-done
		}
	}()
	time.Sleep(100 * time.Millisecond) // le flot a commencé

	cli := startClient(t, cPriv, "10.8.0.2/24", srv.conn.addr(), sPub, fastRetry)
	ping := ipv4("10.8.0.2", "10.8.0.1", "malgré l'attaque")
	cli.dev.in <- ping
	expectPacket(t, srv.dev.out, ping, "vrai client pendant le flot")
	waitLog(t, cli.logs, "cookie reçu")

	stop.Store(true)
	<-done
	n := sent.Load()
	if n < 500 {
		t.Fatalf("flot trop faible pour le test : %d messages", n)
	}
	// Seule la rafale qui précède la détection de charge (le seuil, 50 par seconde)
	// atteint le calcul Diffie-Hellman ; tout le reste est écarté pour un hachage.
	computed := countLogs(srv.logs, "poignée de main illisible")
	if computed > defaultLoadThreshold+5 {
		t.Fatalf("%d messages forgés sur %d ont atteint le calcul Diffie-Hellman", computed, n)
	}
	t.Logf("%d messages forgés envoyés, %d calculés (rafale avant détection), vrai client connecté", n, computed)
}

func TestCookieIsBoundToSourceAddress(t *testing.T) {
	sPriv, sPub := newKey(t)
	cPriv, cPub := newKey(t)
	srv := startServer(t, sPriv, []PeerConfig{{cPub, netip.MustParseAddr("10.8.0.2")}}, fastRetry)
	forceLoad(srv)
	cli := startClient(t, cPriv, "10.8.0.2/24", srv.conn.addr(), sPub, fastRetry)
	waitLog(t, srv.logs, "client 10.8.0.2 connecté")

	// l'attaquant capture la poignée de main qui portait le cookie et la renvoie d'ailleurs
	inits := cli.conn.sentOfType(msgInit, initLen)
	withCookie := inits[len(inits)-1]
	srv.n.mu.Lock()
	srv.n.peers[cPub].lastInit = [timestampLen]byte{} // même sans la protection de l'horodatage
	srv.n.mu.Unlock()
	responses := len(srv.conn.sentOfType(msgResponse, 0))
	cookies := len(srv.conn.sentOfType(msgCookie, 0))
	sendRaw(t, srv.conn.addr(), withCookie)
	deadline := time.Now().Add(2 * time.Second)
	for len(srv.conn.sentOfType(msgCookie, 0)) == cookies && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(srv.conn.sentOfType(msgCookie, 0)) == cookies {
		t.Fatal("le serveur n'a pas exigé de nouveau cookie pour une autre adresse")
	}
	if len(srv.conn.sentOfType(msgResponse, 0)) != responses {
		t.Fatal("le cookie d'une adresse a été accepté depuis une autre")
	}
}

func TestForgedCookieReplyIgnored(t *testing.T) {
	_, sPub := newKey(t)
	cPriv, _ := newKey(t)
	silent := listenLocal(t) // un « serveur » qui ne répond jamais
	defer silent.Close()
	cli := startClient(t, cPriv, "10.8.0.2/24", silent.addr(), sPub, fastRetry)
	cli.dev.in <- ipv4("10.8.0.2", "10.8.0.1", "x")

	deadline := time.Now().Add(2 * time.Second)
	for len(cli.conn.sentOfType(msgInit, initLen)) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cli.n.mu.Lock()
	idx := cli.n.upstream.pending.index
	cli.n.mu.Unlock()
	fake := make([]byte, cookieLen)
	fake[0] = msgCookie
	binary.LittleEndian.PutUint32(fake[4:8], idx)
	rand.Read(fake[8:])
	sendRaw(t, cli.conn.addr(), fake)
	waitLog(t, cli.logs, "cookie invalide ignoré")
	cli.n.mu.Lock()
	defer cli.n.mu.Unlock()
	if !cli.n.upstream.cookie.received.IsZero() {
		t.Fatal("le client a retenu un faux cookie")
	}
}

func TestForgedResponseRejectedBeforeAnyDH(t *testing.T) {
	_, sPub := newKey(t)
	cPriv, _ := newKey(t)
	silent := listenLocal(t)
	defer silent.Close()
	cli := startClient(t, cPriv, "10.8.0.2/24", silent.addr(), sPub, fastRetry)
	cli.dev.in <- ipv4("10.8.0.2", "10.8.0.1", "x")
	deadline := time.Now().Add(2 * time.Second)
	for len(cli.conn.sentOfType(msgInit, initLen)) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cli.n.mu.Lock()
	idx := cli.n.upstream.pending.index
	cli.n.mu.Unlock()
	fake := make([]byte, respLen)
	fake[0] = msgResponse
	rand.Read(fake[4:8])
	binary.LittleEndian.PutUint32(fake[8:12], idx)
	rand.Read(fake[12:])
	sendRaw(t, cli.conn.addr(), fake)
	waitLog(t, cli.logs, "réponse rejetée sans calcul")
	if strings.Contains(cli.logs.String(), "réponse invalide du serveur") {
		t.Fatal("une réponse au mac1 invalide a atteint le déchiffrement Noise")
	}
}

func TestCookieSecretRotatesAndPerIPLimit(t *testing.T) {
	j := newCookieJar(deriveMACKeys(Key{1}))
	t0 := time.Now()
	a := netip.MustParseAddrPort("192.0.2.10:51820")
	b := netip.MustParseAddrPort("192.0.2.11:51820")
	c1 := j.cookieFor(a, t0)
	if c1 != j.cookieFor(a, t0.Add(time.Minute)) {
		t.Fatal("le cookie a changé avant la rotation du secret")
	}
	if c1 == j.cookieFor(b, t0.Add(time.Minute)) {
		t.Fatal("deux adresses ont le même cookie")
	}
	if c1 == j.cookieFor(a, t0.Add(cookieSecretLifetime+time.Second)) {
		t.Fatal("le secret n'a pas été renouvelé après 2 minutes")
	}
	// limite par IP : au plus perIPRate d'affilée
	ok := 0
	for i := 0; i < 50; i++ {
		if j.allowIP(a.Addr(), t0) {
			ok++
		}
	}
	if ok != defaultPerIPRate {
		t.Fatalf("%d poignées de main acceptées d'un coup pour une même IP (attendu %d)", ok, defaultPerIPRate)
	}
	if !j.allowIP(b.Addr(), t0) {
		t.Fatal("une autre adresse est bloquée par la limite de la première")
	}
	j.forget(t0.Add(5 * time.Second))
	if len(j.perIP) != 0 {
		t.Fatal("les compteurs inactifs ne sont pas oubliés")
	}
}

func TestCookieNoncesNeverRepeat(t *testing.T) {
	j := newCookieJar(deriveMACKeys(Key{1}))
	init := forgedInit(Key{1})
	ck := j.cookieFor(netip.MustParseAddrPort("192.0.2.10:1"), time.Now())
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		r := j.cookieReply(init, ck)
		nonce := string(r[8 : 8+cookieNonceLen])
		if seen[nonce] {
			t.Fatal("nonce réutilisé avec la même clé")
		}
		seen[nonce] = true
		if got, ok := openCookie(r, deriveMACKeys(Key{1}), [macLen]byte(init[initLen-macsLen:initLen-macLen])); !ok || got != ck {
			t.Fatal("cookie illisible par le client")
		}
	}
}

func TestLoadEndsAfterAttack(t *testing.T) {
	j := newCookieJar(deriveMACKeys(Key{1}))
	t0 := time.Now()
	for i := 0; i < 200; i++ {
		j.underLoad(t0)
	}
	if !j.underLoad(t0) {
		t.Fatal("200 poignées de main dans la même seconde : le serveur devrait être sous charge")
	}
	if j.underLoad(t0.Add(3 * time.Second)) {
		t.Fatal("la charge persiste alors que l'attaque a cessé")
	}
}

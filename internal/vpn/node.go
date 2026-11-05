package vpn

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
)

// PacketConn : la socket UDP (*net.UDPConn la satisfait).
type PacketConn interface {
	ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error)
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error)
	Close() error
}

// Device : l'interface réseau virtuelle (TUN). Read renvoie un paquet IP émis par le
// système, Write en injecte un comme s'il arrivait du réseau.
type Device interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}

// PeerConfig : un client autorisé à se connecter au serveur.
type PeerConfig struct {
	PublicKey Key
	Address   netip.Addr // son adresse dans le tunnel
}

type ServerConfig struct {
	PrivateKey Key
	Address    netip.Prefix // ex. 10.8.0.1/24 : adresse du serveur et réseau du tunnel
	Peers      []PeerConfig
}

type ClientConfig struct {
	PrivateKey Key
	Address    netip.Prefix   // ex. 10.8.0.2/24
	Server     netip.AddrPort // adresse UDP publique du serveur
	ServerKey  Key            // clé publique du serveur
}

type peer struct {
	publicKey Key
	address   netip.Addr   // serveur : adresse du client dans le tunnel
	allowed   netip.Prefix // sources acceptées dans les paquets déchiffrés de ce pair
	endpoint  netip.AddrPort

	lastInit                [timestampLen]byte
	current, previous, next *session
	pending                 *pendingHandshake
	queue                   [][]byte
	lastSent, lastHandshake time.Time
	warnedNoReply           bool
}

type pendingHandshake struct {
	hs     *noise.HandshakeState
	index  uint32
	sentAt time.Time
	first  time.Time
}

// Node fait tourner un serveur ou un client. Tout l'état est protégé par un seul verrou :
// plus simple à lire qu'un code optimisé, au prix des performances.
type Node struct {
	mu       sync.Mutex
	server   bool
	static   noise.DHKey
	public   Key
	address  netip.Prefix
	conn     PacketConn
	dev      Device
	log      *log.Logger
	debug    *log.Logger
	peers    map[Key]*peer
	byIP     map[netip.Addr]*peer
	sessions map[uint32]*session
	pending  map[uint32]*peer
	upstream *peer
	timing   timing
	limiter  rateLimiter
	now      func() time.Time
	closing  atomic.Bool
}

func newNode(priv Key, addr netip.Prefix, conn PacketConn, dev Device, logger *log.Logger, verbose bool) (*Node, error) {
	if !addr.Addr().Is4() || addr.Bits() >= 32 || addr.Bits() < 8 {
		return nil, fmt.Errorf("adresse du tunnel %s : une adresse IPv4 avec un préfixe de réseau est attendue (ex. 10.8.0.1/24)", addr)
	}
	pub, err := priv.Public()
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	dbg := log.New(io.Discard, "", 0)
	if verbose {
		dbg = logger
	}
	return &Node{
		static:   noise.DHKey{Private: append([]byte(nil), priv[:]...), Public: append([]byte(nil), pub[:]...)},
		public:   pub,
		address:  addr,
		conn:     conn,
		dev:      dev,
		log:      logger,
		debug:    dbg,
		peers:    map[Key]*peer{},
		byIP:     map[netip.Addr]*peer{},
		sessions: map[uint32]*session{},
		pending:  map[uint32]*peer{},
		timing:   defaultTiming,
		limiter:  rateLimiter{rate: 100},
		now:      time.Now,
	}, nil
}

// NewServer prépare un serveur : il attend les poignées de main des clients autorisés.
func NewServer(cfg ServerConfig, conn PacketConn, dev Device, logger *log.Logger, verbose bool) (*Node, error) {
	n, err := newNode(cfg.PrivateKey, cfg.Address, conn, dev, logger, verbose)
	if err != nil {
		return nil, err
	}
	n.server = true
	if len(cfg.Peers) == 0 {
		return nil, errors.New("aucun client autorisé : ajoute au moins un -peer CLÉ=IP")
	}
	for _, pc := range cfg.Peers {
		switch {
		case pc.PublicKey == n.public:
			return nil, errors.New("un client utilise la clé du serveur")
		case !pc.Address.Is4() || !cfg.Address.Contains(pc.Address) || pc.Address == cfg.Address.Addr():
			return nil, fmt.Errorf("adresse client %s : elle doit appartenir à %s et différer de celle du serveur", pc.Address, cfg.Address.Masked())
		case n.peers[pc.PublicKey] != nil:
			return nil, fmt.Errorf("clé client %s déclarée deux fois", pc.PublicKey.Short())
		case n.byIP[pc.Address] != nil:
			return nil, fmt.Errorf("adresse client %s attribuée deux fois", pc.Address)
		}
		p := &peer{publicKey: pc.PublicKey, address: pc.Address, allowed: netip.PrefixFrom(pc.Address, 32)}
		n.peers[pc.PublicKey] = p
		n.byIP[pc.Address] = p
	}
	return n, nil
}

// NewClient prépare un client : il se connecte au serveur et lui envoie le trafic du tunnel.
func NewClient(cfg ClientConfig, conn PacketConn, dev Device, logger *log.Logger, verbose bool) (*Node, error) {
	n, err := newNode(cfg.PrivateKey, cfg.Address, conn, dev, logger, verbose)
	if err != nil {
		return nil, err
	}
	if !cfg.Server.IsValid() {
		return nil, errors.New("adresse du serveur manquante")
	}
	if cfg.ServerKey.IsZero() || cfg.ServerKey == n.public {
		return nil, errors.New("clé publique du serveur manquante ou invalide")
	}
	p := &peer{publicKey: cfg.ServerKey, allowed: cfg.Address.Masked(), endpoint: cfg.Server}
	n.peers[cfg.ServerKey] = p
	n.upstream = p
	return n, nil
}

func (n *Node) PublicKey() Key { return n.public }

// Run fait tourner le nœud jusqu'à l'annulation du contexte.
func (n *Node) Run(ctx context.Context) error {
	errc := make(chan error, 2)
	go func() { errc <- n.udpLoop() }()
	go func() { errc <- n.deviceLoop() }()

	if !n.server {
		n.mu.Lock()
		n.initiate(n.upstream)
		n.mu.Unlock()
	}

	ticker := time.NewTicker(n.timing.tick)
	defer ticker.Stop()
	var err error
	running := 2
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case err = <-errc:
			running--
			break loop
		case <-ticker.C:
			n.mu.Lock()
			n.onTick()
			n.mu.Unlock()
		}
	}
	n.closing.Store(true)
	n.conn.Close()
	n.dev.Close()
	for ; running > 0; running-- {
		<-errc
	}
	return err
}

func (n *Node) udpLoop() error {
	buf := make([]byte, 65535)
	for {
		nr, from, err := n.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if n.closing.Load() {
				return nil
			}
			return fmt.Errorf("lecture UDP : %w", err)
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		n.mu.Lock()
		n.handlePacket(buf[:nr], from)
		n.mu.Unlock()
	}
}

func (n *Node) deviceLoop() error {
	buf := make([]byte, 65535)
	for {
		nr, err := n.dev.Read(buf)
		if err != nil {
			if n.closing.Load() {
				return nil
			}
			return fmt.Errorf("lecture de l'interface : %w", err)
		}
		n.mu.Lock()
		n.fromDevice(buf[:nr])
		n.mu.Unlock()
	}
}

// fromDevice : un paquet émis par le système vers le tunnel. On choisit le pair
// destinataire d'après l'adresse de destination (« routage par clé », comme WireGuard).
func (n *Node) fromDevice(pkt []byte) {
	_, dst, ok := parseIPv4(pkt)
	if !ok {
		return
	}
	var p *peer
	if n.server {
		p = n.byIP[dst]
	} else if n.address.Contains(dst) {
		p = n.upstream
	}
	if p == nil {
		n.debug.Printf("aucun pair pour %s, paquet ignoré", dst)
		return
	}
	n.sendPacket(p, pkt)
}

// sendPacket chiffre et envoie un paquet (nil = keepalive). Sans session utilisable,
// le paquet est mis en attente et le client relance une poignée de main.
func (n *Node) sendPacket(p *peer, payload []byte) {
	now := n.now()
	s := p.current
	if s == nil || s.expired(now, n.timing) || !p.endpoint.IsValid() {
		if len(payload) > 0 {
			if len(p.queue) >= 16 {
				p.queue = p.queue[1:]
			}
			p.queue = append(p.queue, append([]byte(nil), payload...))
		}
		if !n.server {
			n.maybeInitiate(p)
		}
		return
	}
	n.write(p, s.seal(payload))
	p.lastSent = now
	if !n.server && s.initiator && (now.Sub(s.created) >= n.timing.rekeyAfterTime || s.sendCounter >= rekeyAfterMessages) {
		n.maybeInitiate(p)
	}
}

func (n *Node) flushQueue(p *peer) {
	q := p.queue
	p.queue = nil
	for _, pkt := range q {
		n.sendPacket(p, pkt)
	}
}

func (n *Node) write(p *peer, b []byte) {
	if _, err := n.conn.WriteToUDPAddrPort(b, p.endpoint); err != nil {
		n.debug.Printf("envoi vers %s impossible : %v", p.endpoint, err)
	}
}

func (n *Node) newIndex() uint32 {
	var b [4]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			panic(err)
		}
		v := binary.LittleEndian.Uint32(b[:])
		if v != 0 && n.sessions[v] == nil && n.pending[v] == nil {
			return v
		}
	}
}

func (n *Node) maybeInitiate(p *peer) {
	if p.pending != nil && n.now().Sub(p.pending.sentAt) < n.timing.rekeyTimeout {
		return
	}
	n.initiate(p)
}

// initiate envoie le premier message de la poignée de main Noise IK. Le client connaît
// déjà la clé publique du serveur (le « K » de IK) et envoie la sienne chiffrée (le « I »).
func (n *Node) initiate(p *peer) {
	now := n.now()
	first := now
	if p.pending != nil {
		first = p.pending.first
		delete(n.pending, p.pending.index)
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      prologue,
		StaticKeypair: n.static,
		PeerStatic:    p.publicKey[:],
	})
	if err != nil {
		n.log.Printf("poignée de main impossible : %v", err)
		return
	}
	idx := n.newIndex()
	msg := make([]byte, 8, initLen)
	msg[0] = msgInit
	binary.LittleEndian.PutUint32(msg[4:8], idx)
	ts := timestamp(now)
	msg, _, _, err = hs.WriteMessage(msg, ts[:])
	if err != nil {
		n.log.Printf("poignée de main impossible : %v", err)
		return
	}
	p.pending = &pendingHandshake{hs: hs, index: idx, sentAt: now, first: first}
	n.pending[idx] = p
	n.debug.Printf("→ poignée de main envoyée à %s", p.endpoint)
	n.write(p, msg)
}

func (n *Node) handlePacket(pkt []byte, from netip.AddrPort) {
	if len(pkt) < 4 || pkt[1]|pkt[2]|pkt[3] != 0 {
		return
	}
	switch pkt[0] {
	case msgInit:
		if n.server {
			n.handleInit(pkt, from)
		}
	case msgResponse:
		if !n.server {
			n.handleResponse(pkt)
		}
	case msgData:
		n.handleData(pkt, from)
	}
}

// handleInit (serveur) : vérifie qui est le client, puis répond.
func (n *Node) handleInit(pkt []byte, from netip.AddrPort) {
	now := n.now()
	if len(pkt) != initLen {
		return
	}
	if !n.limiter.allow(now) {
		n.debug.Printf("trop de poignées de main, message de %s ignoré", from)
		return
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		Prologue:      prologue,
		StaticKeypair: n.static,
	})
	if err != nil {
		return
	}
	payload, _, _, err := hs.ReadMessage(nil, pkt[8:])
	if err != nil {
		n.debug.Printf("poignée de main illisible depuis %s (mauvaise clé serveur ou message altéré)", from)
		return
	}
	var key Key
	copy(key[:], hs.PeerStatic())
	p := n.peers[key]
	if p == nil {
		n.log.Printf("refusé : clé inconnue %s depuis %s", key.Short(), from)
		return
	}
	if len(payload) != timestampLen || bytes.Compare(payload, p.lastInit[:]) <= 0 {
		n.log.Printf("refusé : poignée de main rejouée ou périmée pour %s, depuis %s", p.address, from)
		return
	}
	copy(p.lastInit[:], payload)

	idx := n.newIndex()
	resp := make([]byte, 12, respLen)
	resp[0] = msgResponse
	binary.LittleEndian.PutUint32(resp[4:8], idx)
	copy(resp[8:12], pkt[4:8])
	resp, cs1, cs2, err := hs.WriteMessage(resp, nil)
	if err != nil || cs1 == nil || cs2 == nil {
		return
	}
	// cs1 chiffre client → serveur, cs2 serveur → client
	s := &session{peer: p, local: idx, remote: binary.LittleEndian.Uint32(pkt[4:8]),
		send: cs2.Cipher(), recv: cs1.Cipher(), created: now}
	n.drop(p.next)
	p.next = s
	n.sessions[idx] = s
	// On répond à l'expéditeur, mais l'adresse du client n'est mise à jour qu'au premier
	// paquet de données authentifié : une poignée de main rejouée (après un redémarrage du
	// serveur, par exemple) ne peut pas détourner le trafic vers l'attaquant.
	n.debug.Printf("← poignée de main de %s, réponse envoyée", p.address)
	if _, err := n.conn.WriteToUDPAddrPort(resp, from); err != nil {
		n.debug.Printf("envoi vers %s impossible : %v", from, err)
	}
}

// handleResponse (client) : termine la poignée de main et active la nouvelle session.
func (n *Node) handleResponse(pkt []byte) {
	if len(pkt) != respLen {
		return
	}
	local := binary.LittleEndian.Uint32(pkt[8:12])
	p := n.pending[local]
	if p == nil || p.pending == nil || p.pending.index != local {
		return
	}
	ph := p.pending
	delete(n.pending, local)
	p.pending = nil
	_, cs1, cs2, err := ph.hs.ReadMessage(nil, pkt[12:])
	if err != nil || cs1 == nil || cs2 == nil {
		n.log.Printf("réponse invalide du serveur : la clé publique du serveur est-elle la bonne ?")
		return
	}
	now := n.now()
	s := &session{peer: p, local: local, remote: binary.LittleEndian.Uint32(pkt[4:8]),
		send: cs1.Cipher(), recv: cs2.Cipher(), created: now, initiator: true, confirmed: true}
	n.sessions[local] = s
	firstTunnel := p.current == nil
	n.promote(p, s)
	p.warnedNoReply = false
	if firstTunnel {
		n.log.Printf("tunnel établi avec %s (poignée de main en %v)", p.endpoint, now.Sub(ph.first).Round(time.Millisecond))
	} else {
		n.debug.Printf("clés renouvelées")
	}
	n.sendPacket(p, nil) // keepalive immédiat : confirme la session auprès du serveur
	n.flushQueue(p)
}

// promote fait de s la session d'envoi. L'ancienne est gardée un moment pour déchiffrer
// les paquets encore en route.
func (n *Node) promote(p *peer, s *session) {
	if p.previous != nil && p.previous != s {
		n.drop(p.previous)
	}
	p.previous = p.current
	p.current = s
	if p.next == s {
		p.next = nil
	}
	p.lastHandshake = n.now()
}

func (n *Node) drop(s *session) {
	if s != nil && n.sessions[s.local] == s {
		delete(n.sessions, s.local)
	}
}

// handleData : déchiffre, vérifie le rejeu et l'adresse source, puis livre le paquet.
func (n *Node) handleData(pkt []byte, from netip.AddrPort) {
	if len(pkt) < dataHeaderLen+tagLen {
		return
	}
	s := n.sessions[binary.LittleEndian.Uint32(pkt[4:8])]
	if s == nil {
		return
	}
	now := n.now()
	if now.Sub(s.created) > n.timing.rejectAfterTime {
		return
	}
	counter := binary.LittleEndian.Uint64(pkt[8:16])
	plain, err := s.recv.Decrypt(nil, counter, pkt[:dataHeaderLen], pkt[dataHeaderLen:])
	if err != nil {
		n.debug.Printf("paquet altéré ou mal chiffré depuis %s, ignoré", from)
		return
	}
	if !s.replay.accept(counter) {
		n.debug.Printf("paquet rejoué depuis %s, ignoré (compteur %d)", from, counter)
		return
	}
	p := s.peer
	if !s.confirmed {
		s.confirmed = true
		n.promote(p, s)
		n.log.Printf("client %s connecté depuis %s", p.address, from)
		p.endpoint = from
		n.flushQueue(p)
	}
	if n.server && p.endpoint != from {
		n.debug.Printf("client %s : nouvelle adresse %s", p.address, from)
		p.endpoint = from // itinérance : le client a changé de réseau
	}
	if len(plain) == 0 {
		return // keepalive
	}
	src, dst, ok := parseIPv4(plain)
	if !ok {
		return
	}
	if !p.allowed.Contains(src) {
		n.log.Printf("refusé : paquet avec une adresse source usurpée (%s) venant du pair %s", src, p.allowed)
		return
	}
	if n.server && dst != n.address.Addr() {
		if other := n.byIP[dst]; other != nil {
			n.sendPacket(other, plain) // trafic entre deux clients : relayé directement
			return
		}
	}
	if _, err := n.dev.Write(plain); err != nil {
		n.debug.Printf("écriture sur l'interface impossible : %v", err)
	}
}

// onTick : expiration des sessions, nouvelles tentatives, renouvellement des clés, keepalive.
func (n *Node) onTick() {
	now := n.now()
	for _, p := range n.peers {
		for _, sp := range []**session{&p.current, &p.previous, &p.next} {
			if *sp != nil && now.Sub((*sp).created) > n.timing.rejectAfterTime {
				n.drop(*sp)
				*sp = nil
			}
		}
		if n.server {
			continue
		}
		if p.pending != nil && now.Sub(p.pending.sentAt) >= n.timing.rekeyTimeout {
			if !p.warnedNoReply && now.Sub(p.pending.first) >= 3*n.timing.rekeyTimeout {
				n.log.Printf("pas de réponse du serveur %s, nouvelles tentatives en cours…", p.endpoint)
				p.warnedNoReply = true
			}
			n.initiate(p)
			continue
		}
		switch {
		case p.current == nil || now.Sub(p.current.created) >= n.timing.rekeyAfterTime:
			n.maybeInitiate(p)
		case now.Sub(p.lastSent) >= n.timing.keepaliveInterval:
			n.sendPacket(p, nil)
		}
	}
}

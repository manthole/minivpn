package vpn

// Format des messages échangés en UDP. Tous les entiers sont en petit-boutiste.
//
//  Poignée de main, client → serveur (116 octets)
//    type=1 | 3 octets à 0 | index de l'expéditeur (4) | message Noise n°1 (108)
//      message Noise n°1 = clé éphémère (32) | clé statique chiffrée (32+16) | horodatage chiffré (12+16)
//
//  Réponse, serveur → client (60 octets)
//    type=2 | 3 octets à 0 | index de l'expéditeur (4) | index du destinataire (4) | message Noise n°2 (48)
//      message Noise n°2 = clé éphémère (32) | charge vide chiffrée (0+16)
//
//  Données, dans les deux sens (32 octets minimum)
//    type=4 | 3 octets à 0 | index du destinataire (4) | compteur (8) | paquet IP chiffré + étiquette (16)
//    Les 16 octets d'en-tête sont authentifiés (données associées de l'AEAD) : on ne peut pas
//    les modifier sans que le déchiffrement échoue. Un paquet de données vide sert de « keepalive ».

import (
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/flynn/noise"
)

const (
	msgInit     = 1
	msgResponse = 2
	msgData     = 4

	tagLen        = 16
	timestampLen  = 12
	initLen       = 8 + 32 + 32 + tagLen + timestampLen + tagLen // 116
	respLen       = 12 + 32 + tagLen                             // 60
	dataHeaderLen = 16

	// TunnelMTU : 1500 (Ethernet) − 20 (IPv4) − 8 (UDP) − 16 (en-tête) − 16 (étiquette) = 1440,
	// arrondi à 1420 comme WireGuard pour laisser de la marge (IPv6, tunnels imbriqués).
	TunnelMTU = 1420

	// Au-delà de 2^60 paquets avec la même clé, on refuse : le compteur sert de nonce et
	// un nonce ne doit jamais être réutilisé avec la même clé.
	rejectAfterMessages = 1 << 60
	rekeyAfterMessages  = 1 << 59
)

// prologue : texte mélangé à la poignée de main. Les deux côtés doivent avoir le même,
// ce qui lie la session à la version du protocole.
var prologue = []byte("minivpn v1")

// Mêmes primitives que WireGuard : X25519, ChaCha20-Poly1305 et BLAKE2s.
var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

// timing regroupe les délais du protocole (inspirés de WireGuard). Les tests les raccourcissent.
type timing struct {
	tick              time.Duration // fréquence des vérifications périodiques
	rekeyAfterTime    time.Duration // le client renouvelle les clés après ce délai
	rejectAfterTime   time.Duration // une session plus vieille est refusée
	rekeyTimeout      time.Duration // délai avant de renvoyer une poignée de main sans réponse
	keepaliveInterval time.Duration // le client envoie un keepalive s'il n'a rien envoyé depuis ce délai
}

var defaultTiming = timing{
	tick:              250 * time.Millisecond,
	rekeyAfterTime:    120 * time.Second,
	rejectAfterTime:   180 * time.Second,
	rekeyTimeout:      5 * time.Second,
	keepaliveInterval: 10 * time.Second,
}

// session : les clés symétriques issues d'une poignée de main réussie.
type session struct {
	peer          *peer
	local, remote uint32 // index choisis par chaque côté pour retrouver la session
	send, recv    noise.Cipher
	sendCounter   uint64
	replay        replayFilter
	created       time.Time
	initiator     bool
	// Côté serveur, une session n'est utilisée pour envoyer qu'après avoir reçu un premier
	// paquet valide du client : cela prouve que le client a bien reçu la réponse et
	// possède les mêmes clés (sinon on enverrait des données que personne ne peut lire).
	confirmed bool
}

// seal chiffre un paquet IP (ou rien, pour un keepalive) et construit le message de données.
func (s *session) seal(payload []byte) []byte {
	out := make([]byte, dataHeaderLen, dataHeaderLen+len(payload)+tagLen)
	out[0] = msgData
	binary.LittleEndian.PutUint32(out[4:8], s.remote)
	binary.LittleEndian.PutUint64(out[8:16], s.sendCounter)
	out = s.send.Encrypt(out, s.sendCounter, out[:dataHeaderLen], payload)
	s.sendCounter++
	return out
}

func (s *session) expired(now time.Time, t timing) bool {
	return now.Sub(s.created) > t.rejectAfterTime || s.sendCounter >= rejectAfterMessages
}

// timestamp produit un horodatage TAI64N (secondes + nanosecondes, gros-boutiste).
// Il est envoyé chiffré dans la poignée de main : le serveur refuse tout horodatage qui
// n'est pas strictement plus récent que le dernier accepté pour ce client. Rejouer une
// poignée de main capturée ne sert donc à rien.
func timestamp(t time.Time) (ts [timestampLen]byte) {
	binary.BigEndian.PutUint64(ts[:8], uint64(t.Unix())+0x400000000000000a)
	binary.BigEndian.PutUint32(ts[8:], uint32(t.Nanosecond()))
	return ts
}

// parseIPv4 lit les adresses source et destination d'un paquet IPv4.
// Les autres paquets (IPv6 notamment) ne sont pas gérés par ce projet.
func parseIPv4(pkt []byte) (src, dst netip.Addr, ok bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return src, dst, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl || int(binary.BigEndian.Uint16(pkt[2:4])) < ihl {
		return src, dst, false
	}
	return netip.AddrFrom4([4]byte(pkt[12:16])), netip.AddrFrom4([4]byte(pkt[16:20])), true
}

// rateLimiter limite le nombre de poignées de main traitées par seconde. Chacune coûte
// plusieurs calculs Diffie-Hellman : sans limite, un flot de faux messages saturerait le
// processeur du serveur. (WireGuard va plus loin avec un mécanisme de « cookies ».)
type rateLimiter struct {
	tokens float64
	last   time.Time
	rate   float64
}

func (r *rateLimiter) allow(now time.Time) bool {
	if r.last.IsZero() {
		r.tokens = r.rate
	} else {
		r.tokens += now.Sub(r.last).Seconds() * r.rate
		if r.tokens > r.rate {
			r.tokens = r.rate
		}
	}
	r.last = now
	if r.tokens < 1 {
		return false
	}
	r.tokens--
	return true
}

package vpn

// Protection contre le déni de service, reprise de WireGuard (livre blanc, section 5.4.7).
//
// Chaque message de poignée de main se termine par deux codes d'authentification de 16 octets :
//
//	mac1 = MAC(HASH("mac1----" ‖ clé publique du destinataire), message jusqu'à mac1)
//	mac2 = MAC(cookie, message jusqu'à mac2)        (16 zéros si l'on n'a pas de cookie)
//
// mac1 ne peut être calculé que par qui connaît la clé publique du serveur. Le serveur le
// vérifie avant tout calcul Diffie-Hellman : un flot de messages forgés ne lui coûte qu'un
// hachage BLAKE2s par paquet.
//
// Quand le serveur est « sous charge », il exige en plus un mac2 valide. Aux messages qui
// n'en ont pas, il ne répond qu'un petit message « cookie » et s'arrête là. Le cookie vaut
// MAC(secret renouvelé toutes les 2 minutes, IP:port de l'expéditeur) : seul un client qui
// reçoit vraiment les paquets envoyés à son adresse peut l'obtenir. Une adresse usurpée ne
// reçoit rien, ne peut pas calculer mac2, et ses messages sont écartés pour le prix d'un
// hachage. Les vrais clients, eux, renvoient leur poignée de main avec le cookie et passent.
//
// Le cookie voyage chiffré (XChaCha20-Poly1305, clé dérivée de la clé publique du serveur)
// et lié au mac1 du message auquel il répond (données associées) : un tiers ne peut ni le
// lire, ni fabriquer un faux cookie qu'un client accepterait.
//
// Format du message cookie, serveur → client (64 octets) :
//
//	type=3 | 3 octets à 0 | index du destinataire (4) | nonce (24) | cookie chiffré (16+16)

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"net/netip"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	msgCookie = 3

	macLen         = 16
	macsLen        = 2 * macLen
	cookieNonceLen = chacha20poly1305.NonceSizeX // 24
	cookieLen      = 8 + cookieNonceLen + macLen + tagLen

	// Le secret du serveur change toutes les 2 minutes ; le client considère son cookie
	// périmé un peu avant (5 s de marge pour le temps de transit), comme WireGuard.
	cookieSecretLifetime = 2 * time.Minute
	cookieValidity       = cookieSecretLifetime - 5*time.Second

	// Au-delà de ce nombre de poignées de main par seconde (mac1 valide), le serveur se
	// déclare sous charge pendant une seconde et exige un cookie.
	defaultLoadThreshold = 50
	// Sous charge, chaque adresse IP qui a prouvé qu'elle reçoit ses paquets reste limitée.
	defaultPerIPRate = 10
)

var (
	labelMAC1   = []byte("mac1----")
	labelCookie = []byte("cookie--")
)

func hash(parts ...[]byte) (out [32]byte) {
	h, _ := blake2s.New256(nil)
	for _, p := range parts {
		h.Write(p)
	}
	copy(out[:], h.Sum(nil))
	return out
}

// mac : BLAKE2s avec clé, tronqué à 16 octets (le « MAC » de WireGuard).
func mac(key []byte, msg []byte) (out [macLen]byte) {
	h, err := blake2s.New128(key)
	if err != nil {
		panic(err) // clé de 16 ou 32 octets : ne peut pas arriver
	}
	h.Write(msg)
	copy(out[:], h.Sum(nil))
	return out
}

// macKeys : les deux clés dérivées de la clé publique d'un destinataire.
type macKeys struct {
	mac1   [32]byte // HASH("mac1----" ‖ clé publique)
	cookie [32]byte // HASH("cookie--" ‖ clé publique)
}

func deriveMACKeys(pub Key) macKeys {
	return macKeys{mac1: hash(labelMAC1, pub[:]), cookie: hash(labelCookie, pub[:])}
}

// clientCookie : ce que le client retient du dernier cookie reçu de son serveur.
type clientCookie struct {
	value    [macLen]byte
	received time.Time
}

func (c *clientCookie) fresh(now time.Time) bool {
	return !c.received.IsZero() && now.Sub(c.received) < cookieValidity
}

// appendMACs ajoute mac1 (clé du destinataire) et mac2 (cookie s'il est encore valable).
// Elle renvoie aussi mac1, qui servira à vérifier un éventuel message cookie en retour.
func appendMACs(msg []byte, to macKeys, ck *clientCookie, now time.Time) ([]byte, [macLen]byte) {
	m1 := mac(to.mac1[:], msg)
	msg = append(msg, m1[:]...)
	var m2 [macLen]byte
	if ck != nil && ck.fresh(now) {
		m2 = mac(ck.value[:], msg)
	}
	return append(msg, m2[:]...), m1
}

// validMAC1 vérifie mac1 d'un message reçu, avec la clé dérivée de notre propre clé publique.
func validMAC1(msg []byte, own macKeys) bool {
	if len(msg) < macsLen {
		return false
	}
	body := len(msg) - macsLen
	want := mac(own.mac1[:], msg[:body])
	return subtle.ConstantTimeCompare(want[:], msg[body:body+macLen]) == 1
}

// cookieJar : côté serveur, le secret tournant et la détection de charge.
//
// Sous un flot, le serveur répond un cookie à chaque message : ce chemin doit coûter le
// moins possible. Le chiffrement est préparé une fois, et le nonce de 24 octets est un
// préfixe aléatoire tiré au démarrage suivi d'un compteur : unique sans appel système.
type cookieJar struct {
	secret    [32]byte
	secretAt  time.Time
	aead      cipher.AEAD
	nonceBase [cookieNonceLen - 8]byte
	nonceCtr  uint64
	load      rateLimiter // poignées de main (mac1 valide) par seconde
	loadUntil time.Time
	loaded    bool // pour ne journaliser que les changements d'état
	perIPRate float64
	perIP     map[netip.Addr]*rateLimiter
}

func newCookieJar(own macKeys) cookieJar {
	aead, err := chacha20poly1305.NewX(own.cookie[:])
	if err != nil {
		panic(err)
	}
	j := cookieJar{aead: aead, load: rateLimiter{rate: defaultLoadThreshold},
		perIPRate: defaultPerIPRate, perIP: map[netip.Addr]*rateLimiter{}}
	if _, err := rand.Read(j.nonceBase[:]); err != nil {
		panic(err)
	}
	return j
}

// cookieFor calcule le cookie d'une adresse : MAC(secret, IP ‖ port).
func (j *cookieJar) cookieFor(from netip.AddrPort, now time.Time) [macLen]byte {
	if j.secretAt.IsZero() || now.Sub(j.secretAt) >= cookieSecretLifetime {
		if _, err := rand.Read(j.secret[:]); err != nil {
			panic(err)
		}
		j.secretAt = now
	}
	ip := from.Addr().Unmap().As16()
	var buf [18]byte
	copy(buf[:16], ip[:])
	binary.BigEndian.PutUint16(buf[16:], from.Port())
	return mac(j.secret[:], buf[:])
}

// validMAC2 : le message porte-t-il ce cookie (celui de l'adresse qui l'envoie) ?
func validMAC2(msg []byte, ck [macLen]byte) bool {
	body := len(msg) - macLen
	want := mac(ck[:], msg[:body])
	return subtle.ConstantTimeCompare(want[:], msg[body:]) == 1
}

// underLoad compte la poignée de main reçue et dit si le serveur est sous charge.
// Il le reste une seconde après le dernier dépassement du seuil.
func (j *cookieJar) underLoad(now time.Time) bool {
	if !j.load.allow(now) {
		j.loadUntil = now.Add(time.Second)
	}
	return now.Before(j.loadUntil)
}

// allowIP : limite par adresse, appliquée sous charge aux messages qui ont un cookie valide.
func (j *cookieJar) allowIP(ip netip.Addr, now time.Time) bool {
	l := j.perIP[ip]
	if l == nil {
		l = &rateLimiter{rate: j.perIPRate}
		j.perIP[ip] = l
	}
	return l.allow(now)
}

// forget supprime les compteurs par IP inactifs (appelé périodiquement).
func (j *cookieJar) forget(now time.Time) {
	for ip, l := range j.perIP {
		if now.Sub(l.last) > 2*time.Second {
			delete(j.perIP, ip)
		}
	}
}

// cookieReply construit le message cookie (ck : cookie de l'expéditeur) en réponse à une
// poignée de main. Le cookie est chiffré et lié au mac1 de cette poignée de main.
func (j *cookieJar) cookieReply(init []byte, ck [macLen]byte) []byte {
	out := make([]byte, 8+cookieNonceLen, cookieLen)
	out[0] = msgCookie
	copy(out[4:8], init[4:8]) // index choisi par le client pour sa poignée de main
	copy(out[8:], j.nonceBase[:])
	binary.LittleEndian.PutUint64(out[8+len(j.nonceBase):], j.nonceCtr)
	j.nonceCtr++
	body := len(init) - macsLen
	return j.aead.Seal(out, out[8:8+cookieNonceLen], ck[:], init[body:body+macLen])
}

// openCookie (client) : déchiffre un message cookie lié au mac1 de notre poignée de main.
func openCookie(pkt []byte, server macKeys, sentMAC1 [macLen]byte) ([macLen]byte, bool) {
	var ck [macLen]byte
	aead, err := chacha20poly1305.NewX(server.cookie[:])
	if err != nil {
		return ck, false
	}
	plain, err := aead.Open(nil, pkt[8:8+cookieNonceLen], pkt[8+cookieNonceLen:], sentMAC1[:])
	if err != nil || len(plain) != macLen {
		return ck, false
	}
	copy(ck[:], plain)
	return ck, true
}

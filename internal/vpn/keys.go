package vpn

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Key est une clé Curve25519 (X25519) de 32 octets, privée ou publique.
// Elle s'écrit en Base64, comme les clés WireGuard.
type Key [32]byte

func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// Short renvoie un début de clé lisible pour les journaux.
func (k Key) Short() string { return k.String()[:8] + "…" }

func (k Key) IsZero() bool { return k == Key{} }

// ParseKey lit une clé en Base64.
func ParseKey(s string) (Key, error) {
	var k Key
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return k, fmt.Errorf("clé invalide (Base64 attendu) : %w", err)
	}
	if len(b) != len(k) {
		return k, fmt.Errorf("clé invalide : %d octets au lieu de %d", len(b), len(k))
	}
	copy(k[:], b)
	return k, nil
}

// GeneratePrivateKey tire une clé privée X25519 avec le générateur aléatoire du système.
func GeneratePrivateKey() (Key, error) {
	var k Key
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return k, err
	}
	copy(k[:], priv.Bytes())
	return k, nil
}

// Public calcule la clé publique correspondant à une clé privée.
func (k Key) Public() (Key, error) {
	var pub Key
	priv, err := ecdh.X25519().NewPrivateKey(k[:])
	if err != nil {
		return pub, err
	}
	copy(pub[:], priv.PublicKey().Bytes())
	return pub, nil
}

// WritePrivateKey enregistre une clé privée lisible par son seul propriétaire (0600).
// Elle refuse d'écraser un fichier existant, pour ne jamais perdre une clé par erreur.
func WritePrivateKey(path string, k Key) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s existe déjà : supprime-le d'abord si tu veux vraiment le remplacer", path)
		}
		return err
	}
	if _, err := f.WriteString(k.String() + "\n"); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// LoadPrivateKey lit une clé privée et prévient si le fichier est lisible par d'autres utilisateurs.
func LoadPrivateKey(path string) (Key, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Key{}, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "attention : %s est lisible par d'autres utilisateurs (chmod 600 %s)\n", path, path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Key{}, err
	}
	return ParseKey(string(b))
}

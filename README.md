# minivpn

[![tests](https://github.com/manthole/minivpn/actions/workflows/tests.yml/badge.svg)](https://github.com/manthole/minivpn/actions/workflows/tests.yml)

Un VPN écrit de zéro en Go, pour comprendre comment fonctionne un tunnel chiffré.
Il reprend l'architecture de [WireGuard](https://www.wireguard.com/) : poignée de main
**Noise IK**, chiffrement **ChaCha20-Poly1305**, transport **UDP**, interface réseau
virtuelle **TUN**. Il tourne sur **macOS** et **Linux**.

> ⚠️ **Projet d'apprentissage.** Il n'a pas été audité et laisse volontairement de côté
> plusieurs protections de WireGuard (voir [Limites](#limites-connues)). Pour protéger du
> vrai trafic, utilise WireGuard.

## Ce que fait le projet

```
   Mac (client)                                         Serveur (Docker, VPS…)
 ┌────────────────────┐                                ┌────────────────────┐
 │ ping 10.8.0.1      │                                │ page web           │
 │ curl 10.8.0.1:8080 │                                │ sur 10.8.0.1:8080  │
 └─────────┬──────────┘                                └─────────▲──────────┘
           │ paquet IP en clair                                  │ paquet IP en clair
 ┌─────────▼──────────┐                                ┌─────────┴──────────┐
 │ utun5  10.8.0.2    │                                │ minivpn0  10.8.0.1 │
 └─────────┬──────────┘                                └─────────▲──────────┘
           │                 Internet / réseau local               │
 ┌─────────▼──────────┐   UDP : en-tête + paquet chiffré  ┌─────────┴──────────┐
 │  minivpn client    ├──────────────────────────────────►│  minivpn server    │
 │  chiffre           │◄──────────────────────────────────┤  déchiffre, vérifie│
 └────────────────────┘                                    └────────────────────┘
```

Le système envoie les paquets destinés au réseau du tunnel (10.8.0.0/24) à l'interface
virtuelle. `minivpn` les lit, les chiffre, les envoie en UDP au serveur, qui les
déchiffre, les vérifie et les réinjecte dans son propre système. Les réponses font le
chemin inverse.

## Comment ça marche

### 1. La poignée de main (Noise IK)

Avant d'échanger des données, client et serveur se mettent d'accord sur des clés de
session en **deux messages**, avec le schéma `Noise_IK_25519_ChaChaPoly_BLAKE2s` (celui de
WireGuard, sans la clé pré-partagée). L'implémentation de Noise utilisée est la
bibliothèque [flynn/noise](https://github.com/flynn/noise) : aucune cryptographie n'est
codée à la main.

- **I** : le client envoie sa clé publique, chiffrée. Un observateur ne sait pas qui se connecte.
- **K** : le client connaît déjà la clé publique du serveur. Un faux serveur ne peut pas répondre.
- Chaque côté tire une **clé éphémère** : même si une clé privée est volée plus tard, le
  trafic déjà capturé reste indéchiffrable (**confidentialité persistante**).

Le serveur n'accepte que les clés publiques déclarées avec `-peer`. Un inconnu ne reçoit
**aucune réponse** : le serveur est invisible pour qui n'a pas la bonne clé.

Le premier message contient un **horodatage chiffré**. Le serveur refuse tout horodatage
qui n'est pas plus récent que le dernier accepté pour ce client : rejouer une poignée de
main capturée ne sert à rien.

### 2. Les données

```
 type=4 │ 000 │ index destinataire (4) │ compteur (8) │ paquet IP chiffré │ étiquette (16)
 └──────────── en-tête de 16 octets, authentifié ────┘
```

- Chaque paquet est chiffré et authentifié avec **ChaCha20-Poly1305**. Modifier un seul
  bit, même dans l'en-tête, fait échouer le déchiffrement.
- Le **compteur** sert de nonce et augmente à chaque paquet. Une **fenêtre glissante**
  (RFC 6479) rejette tout paquet déjà reçu, tout en tolérant le désordre et les pertes
  d'UDP. Elle n'est mise à jour qu'*après* authentification, sinon un attaquant pourrait
  la faire avancer avec de faux compteurs.
- **Routage par clé** : chaque client a une adresse dans le tunnel. Le serveur rejette un
  paquet dont l'adresse source ne correspond pas à la clé qui l'a chiffré. Un client
  authentifié ne peut donc pas se faire passer pour un autre.

### 3. La vie du tunnel

- Le client **renouvelle les clés toutes les 2 minutes**. Une session de plus de
  3 minutes est refusée. L'ancienne session est gardée le temps de déchiffrer les paquets
  encore en route : le renouvellement ne coupe rien.
- Côté serveur, une nouvelle session n'est utilisée pour envoyer qu'après un premier
  paquet valide du client : c'est la preuve que le client a bien reçu la réponse.
- Le client envoie un **keepalive** toutes les 10 secondes, pour garder ouverte la
  traduction d'adresses (NAT) de sa box.
- **Itinérance** : si le client change de réseau (Wi-Fi → 4G), le serveur suit sa
  nouvelle adresse dès le premier paquet authentifié.
- Les poignées de main sont **limitées à 100 par seconde**, pour qu'un flot de faux
  messages ne sature pas le processeur.

## Ce qui est testé

| Test | Ce qu'il vérifie |
|---|---|
| `TestTunnelBothWays` | Échange dans les deux sens, et aucun contenu en clair sur le réseau |
| `TestUnknownClientRejected` | Une clé non autorisée n'obtient aucune réponse |
| `TestWrongServerKey` | Un client qui vise un autre serveur ne peut rien envoyer |
| `TestReplayedHandshakeRejected` | Une poignée de main rejouée est refusée |
| `TestReplayAfterServerRestartCannotHijack` | Même après un redémarrage du serveur, une poignée de main rejouée ne détourne pas le trafic |
| `TestReplayedAndTamperedDataRejected` | Paquet rejoué, chiffré altéré, en-tête altéré : tous rejetés |
| `TestSpoofedSourceRejected` | Un client ne peut pas usurper l'adresse d'un autre |
| `TestClientToClientRelay` | Deux clients se parlent à travers le serveur |
| `TestRekeyKeepsTrafficFlowing` | Aucun paquet perdu pendant les renouvellements de clés |
| `TestReplayFilter…` | La fenêtre anti-rejeu, cas limites compris |
| `TestDeviceRoundTrip` (root) | Vraie interface (`utun` sur macOS, TUN sur Linux) : un paquet sort par l'interface, une réponse injectée arrive à l'application |
| `TestRealTunnel` (Linux, root) | Vrai binaire, vraie interface : ping et échange UDP avec le noyau, capture réseau sans contenu en clair, nettoyage à l'arrêt |

L'intégration continue GitHub lance tous ces tests à chaque publication, sur Linux **et
sur un vrai Mac** (voir le badge en haut de page).

```sh
go test -race ./...                              # tests sans droits administrateur
sudo go test -tags e2e ./internal/tun/ -v        # vraie interface (macOS ou Linux)
./scripts/test-e2e.sh                            # tunnel complet réel (Linux)
```

## Démarrage rapide sur macOS

Prérequis : [Homebrew](https://brew.sh), puis `brew install go`, et
[Docker Desktop](https://www.docker.com/products/docker-desktop/) pour le serveur.

```sh
# 1. compiler
go mod tidy          # télécharge les bibliothèques et vérifie leurs empreintes
go build -o minivpn .

# 2. clé du client
./minivpn genkey -out client.key

# 3. serveur dans Docker (il crée sa clé dans ./data au premier lancement)
docker build -t minivpn .
docker run --rm -it --name minivpn \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -p 51820:51820/udp -v "$PWD/data:/data" \
  -e CLIENT_PUBKEY="$(./minivpn pubkey -key client.key)" \
  minivpn

# 4. dans un autre terminal : le client
sudo ./minivpn client -key client.key \
  -server 127.0.0.1:51820 -server-key "$(cat data/server.pub)" \
  -addr 10.8.0.2/24

# 5. dans un troisième terminal
ping 10.8.0.1
curl http://10.8.0.1:8080
```

`Ctrl+C` arrête le client : l'interface `utunN` et sa route disparaissent.
Ajoute `-v` au client ou `-e VERBOSE=1` au conteneur pour un journal détaillé.

## Commandes

```
minivpn genkey -out FICHIER     crée une clé privée (droits 600) et affiche la clé publique
minivpn pubkey -key FICHIER     affiche la clé publique
minivpn server -key server.key -listen :51820 -addr 10.8.0.1/24 -peer CLÉ=10.8.0.2 [-peer …]
minivpn client -key client.key -server HÔTE:PORT -server-key CLÉ -addr 10.8.0.2/24
```

## Limites connues

Choix volontaires pour garder le code lisible, ou fonctions pas encore écrites :

- **Pas de mécanisme de cookies** contre le déni de service : seulement une limite
  globale de poignées de main. Un attaquant peut donc gêner les connexions légitimes.
- **Horodatages en mémoire** : après un redémarrage du serveur, une ancienne poignée de
  main capturée est acceptée une fois. Elle ne donne accès à rien (l'attaquant n'a pas les
  clés) et ne détourne pas le trafic (testé), mais elle fait calculer une réponse au serveur.
- **Pas de clé pré-partagée**, donc pas de couche de résistance aux futurs ordinateurs quantiques.
- **IPv4 seulement**, et **tunnel partiel** : seul le réseau du tunnel passe par le VPN,
  pas tout ton trafic internet.
- **Un seul verrou** pour tout l'état : simple à lire, mais lent sous forte charge.
- Sur macOS, l'interface `utun` est testée pour de vrai par l'intégration continue, mais le
  tunnel complet de bout en bout n'est testé automatiquement que sous Linux.

## Pour aller plus loin

- **Tunnel complet** : faire passer tout le trafic par un serveur loué (VPS), avec la
  traduction d'adresses (NAT) côté serveur et une route d'exception vers le serveur.
- IPv6, mécanisme de cookies, fichier de configuration, menu dans la barre de macOS.

## Structure

```
main.go                  ligne de commande
internal/vpn/            protocole : clés, messages, poignée de main, sessions, anti-rejeu
internal/tun/            interface virtuelle (utun sur macOS, /dev/net/tun sur Linux)
internal/netcfg/         adresse et route de l'interface
internal/e2e/            test réel (Linux, root)
docker/, Dockerfile      serveur de démonstration
```

## Crédits

Protocole [Noise](https://noiseprotocol.org/) de Trevor Perrin, architecture inspirée de
[WireGuard](https://www.wireguard.com/papers/wireguard.pdf) de Jason A. Donenfeld,
implémentation Noise [flynn/noise](https://github.com/flynn/noise).

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
bibliothèque [flynn/noise](https://github.com/flynn/noise), et les codes mac1/mac2 et le
chiffrement des cookies viennent de `golang.org/x/crypto` : aucune cryptographie n'est
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

Les messages ont la taille et la structure de ceux de WireGuard : 148 octets pour la
poignée de main, 92 pour la réponse, 64 pour un cookie (voir ci-dessous).

### 2. La résistance au déni de service (mac1, cookies)

Une poignée de main coûte au serveur plusieurs calculs Diffie-Hellman. Un attaquant qui
en envoie des milliers par seconde peut saturer son processeur. Comme WireGuard, chaque
message de poignée de main se termine donc par deux codes d'authentification (BLAKE2s) :

```
 … message Noise … │ mac1 (16) │ mac2 (16)
   mac1 = MAC(HASH("mac1----" ‖ clé publique du serveur), message)
   mac2 = MAC(cookie, message + mac1)             16 zéros sans cookie
```

- **mac1** prouve que l'expéditeur connaît la clé publique du serveur. Il est vérifié
  *avant* tout calcul Diffie-Hellman : un message forgé ou destiné à un autre serveur est
  rejeté pour le prix d'un hachage.
- **Sous charge** (plus de 50 poignées de main par seconde), le serveur exige aussi
  **mac2**. Sans mac2 valide, il ne calcule rien et répond un petit message **cookie** :
  `MAC(secret renouvelé toutes les 2 minutes, IP:port de l'expéditeur)`, chiffré en
  XChaCha20-Poly1305 et lié au mac1 du message (un tiers ne peut ni le lire ni en forger).
- Un vrai client reçoit ce cookie et le présente à sa tentative suivante : il passe. Une
  **adresse usurpée ne reçoit jamais le cookie**, donc ses messages restent bloqués pour
  le prix d'un hachage. Seuls les clients qui prouvent qu'ils reçoivent les paquets envoyés
  à leur adresse font calculer le serveur, chacun dans la limite de 10 poignées de main
  par seconde et par adresse.

```
 client                          serveur sous charge
   │── poignée de main (mac2 = 0) ──►│  mac1 OK, mac2 absent : aucun calcul
   │◄──────────── cookie ────────────│  cookie = MAC(secret, IP:port du client)
   │── poignée de main (mac2 OK) ───►│  adresse prouvée : calcul Diffie-Hellman
   │◄──────────── réponse ───────────│
```

**Mesuré** (tests de charge sur une machine à 2 cœurs, attaquant sur la même machine) :
jusqu'à 60 000 poignées de main forgées par seconde, le vrai client se connecte à chaque
fois en une relance (150 ms avec les délais des tests, 5 s en temps normal), et le serveur
ne fait de calcul Diffie-Hellman que pour les 50 premiers messages, le temps de détecter la
charge. L'ancienne version, avec une simple limite globale de 100 par seconde, calculait
pour l'attaquant en continu et laissait le vrai client tirer au sort sa place parmi les faux
messages. Au-delà d'environ 200 000 paquets par seconde, la machine ne lit même plus tous
les paquets : c'est une attaque **volumétrique**, contre laquelle aucun protocole ne peut
rien. Elle se filtre en amont, chez l'hébergeur ou l'opérateur.

### 3. Les données

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

### 4. La vie du tunnel

- Le client **renouvelle les clés toutes les 2 minutes**. Une session de plus de
  3 minutes est refusée. L'ancienne session est gardée le temps de déchiffrer les paquets
  encore en route : le renouvellement ne coupe rien.
- Côté serveur, une nouvelle session n'est utilisée pour envoyer qu'après un premier
  paquet valide du client : c'est la preuve que le client a bien reçu la réponse.
- Le client envoie un **keepalive** toutes les 10 secondes, pour garder ouverte la
  traduction d'adresses (NAT) de sa box.
- **Itinérance** : si le client change de réseau (Wi-Fi → 4G), le serveur suit sa
  nouvelle adresse dès le premier paquet authentifié.

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
| `TestForgedHandshakeRejectedBeforeAnyDH` | Un message au mac1 invalide est rejeté sans calcul ni réponse |
| `TestCookieLetsClientInUnderLoad` | Sous charge, le client reçoit un cookie, le présente et se connecte |
| `TestFloodOfSpoofedHandshakesDoesNotLockOutClient` | Pendant un flot de poignées de main forgées, le vrai client se connecte, et seule la rafale initiale fait calculer le serveur |
| `TestCookieIsBoundToSourceAddress` | Un cookie capturé ne sert à rien depuis une autre adresse |
| `TestForgedCookieReplyIgnored` | Un faux message cookie est ignoré par le client |
| `TestForgedResponseRejectedBeforeAnyDH` | Une fausse réponse au mac1 invalide est rejetée sans calcul |
| `TestCookieSecretRotatesAndPerIPLimit`, `TestCookieNoncesNeverRepeat`, `TestLoadEndsAfterAttack` | Rotation du secret, limite par adresse, nonces uniques, fin de la charge |
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

- **Déni de service volumétrique** : mac1 et les cookies empêchent de faire calculer le
  serveur, mais pas de saturer sa connexion ou sa capacité à lire les paquets. Ça se
  filtre en amont. Le seuil de charge est fixe (50 poignées de main par seconde) là où
  WireGuard mesure la longueur de sa file d'attente.
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
- IPv6, fichier de configuration, menu dans la barre de macOS.

## Structure

```
main.go                  ligne de commande
internal/vpn/            protocole : clés, messages, poignée de main, cookies, sessions, anti-rejeu
internal/tun/            interface virtuelle (utun sur macOS, /dev/net/tun sur Linux)
internal/netcfg/         adresse et route de l'interface
internal/e2e/            test réel (Linux, root)
docker/, Dockerfile      serveur de démonstration
```

## Crédits

Protocole [Noise](https://noiseprotocol.org/) de Trevor Perrin, architecture inspirée de
[WireGuard](https://www.wireguard.com/papers/wireguard.pdf) de Jason A. Donenfeld,
implémentation Noise [flynn/noise](https://github.com/flynn/noise).

## Licence

Code et documentation sous [licence MIT](LICENSE) © 2026 Manthole : libre réutilisation, y compris commerciale, à condition de conserver la mention de copyright.

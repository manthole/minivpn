#!/bin/sh
# Démarre le serveur minivpn dans le conteneur, puis une page web sur 10.8.0.1:8080,
# une adresse qui n'existe qu'à l'intérieur du tunnel.
set -eu

KEY=/data/server.key
if [ ! -f "$KEY" ]; then
	minivpn genkey -out "$KEY" >/dev/null 2>&1
fi
minivpn pubkey -key "$KEY" >/data/server.pub
echo "clé publique du serveur : $(cat /data/server.pub)  (aussi écrite dans data/server.pub)"

if [ -z "${CLIENT_PUBKEY:-}" ]; then
	echo "erreur : définis CLIENT_PUBKEY avec la clé publique du client (-e CLIENT_PUBKEY=...)" >&2
	exit 1
fi

mkdir -p /www
cat >/www/index.html <<'HTML'
<!doctype html><meta charset="utf-8"><title>minivpn</title>
<h1>Bravo, tu es dans le tunnel minivpn</h1>
<p>Cette page est servie sur 10.8.0.1, une adresse joignable uniquement à travers le VPN.</p>
HTML

minivpn server -key "$KEY" -listen :51820 -addr 10.8.0.1/24 -peer "$CLIENT_PUBKEY=10.8.0.2" ${VERBOSE:+-v} &
pid=$!
trap 'kill -TERM "$pid" 2>/dev/null' TERM INT

# httpd ne peut écouter sur 10.8.0.1 qu'une fois l'interface configurée
for _ in $(seq 1 50); do
	if httpd -p 10.8.0.1:8080 -h /www 2>/dev/null; then
		echo "page de test : http://10.8.0.1:8080 (depuis le client, une fois connecté)"
		break
	fi
	sleep 0.2
done

wait "$pid"

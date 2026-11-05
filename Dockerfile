# Serveur minivpn de démonstration, pour tester depuis un Mac avec Docker Desktop.
# Voir le README, section « Démarrage rapide ».

FROM golang:1.24-alpine AS build
WORKDIR /src
COPY . .
RUN go mod tidy && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/minivpn .

FROM alpine:3.20
# busybox-extras fournit httpd : une petite page web joignable uniquement par le tunnel
RUN apk add --no-cache busybox-extras
COPY --from=build /out/minivpn /usr/local/bin/minivpn
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
VOLUME /data
EXPOSE 51820/udp
ENTRYPOINT ["/entrypoint.sh"]

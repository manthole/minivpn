// minivpn : un VPN pédagogique, inspiré de WireGuard.
// Poignée de main Noise IK, chiffrement ChaCha20-Poly1305, transport UDP, interface TUN.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/manthole/minivpn/internal/netcfg"
	"github.com/manthole/minivpn/internal/tun"
	"github.com/manthole/minivpn/internal/vpn"
)

const version = "0.1.0"

const usage = `minivpn ` + version + ` — un VPN pédagogique (Noise IK + ChaCha20-Poly1305 sur UDP)

Utilisation :
  minivpn genkey -out FICHIER     crée une clé privée et affiche la clé publique
  minivpn pubkey -key FICHIER     affiche la clé publique d'une clé privée
  minivpn server [options]        lance le serveur (Linux ou macOS, avec sudo)
  minivpn client [options]        lance le client (Linux ou macOS, avec sudo)

« minivpn server -h » ou « minivpn client -h » détaille les options.
Projet d'apprentissage : pour protéger du vrai trafic, utilise WireGuard.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "genkey":
		err = cmdGenkey(os.Args[2:])
	case "pubkey":
		err = cmdPubkey(os.Args[2:])
	case "server":
		err = cmdServer(os.Args[2:])
	case "client":
		err = cmdClient(os.Args[2:])
	case "version", "-version", "--version":
		fmt.Println("minivpn", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "commande inconnue : %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "erreur :", err)
		os.Exit(1)
	}
}

func cmdGenkey(args []string) error {
	fs := flag.NewFlagSet("genkey", flag.ExitOnError)
	out := fs.String("out", "", "fichier où écrire la clé privée (créé avec les droits 600)")
	fs.Parse(args)
	if *out == "" {
		return errors.New("précise le fichier avec -out, par exemple : minivpn genkey -out client.key")
	}
	priv, err := vpn.GeneratePrivateKey()
	if err != nil {
		return err
	}
	pub, err := priv.Public()
	if err != nil {
		return err
	}
	if err := vpn.WritePrivateKey(*out, priv); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "clé privée écrite dans %s (à garder secrète)\nclé publique (à partager) :\n", *out)
	fmt.Println(pub)
	return nil
}

func cmdPubkey(args []string) error {
	fs := flag.NewFlagSet("pubkey", flag.ExitOnError)
	keyPath := fs.String("key", "", "fichier de la clé privée")
	fs.Parse(args)
	if *keyPath == "" {
		return errors.New("précise le fichier avec -key")
	}
	priv, err := vpn.LoadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	pub, err := priv.Public()
	if err != nil {
		return err
	}
	fmt.Println(pub)
	return nil
}

// peerList lit les options -peer CLÉ=IP répétées.
type peerList []vpn.PeerConfig

func (l *peerList) String() string { return fmt.Sprint(len(*l), " client(s)") }

func (l *peerList) Set(v string) error {
	// la clé en Base64 se termine elle-même par « = » : on coupe sur le DERNIER signe égal
	i := strings.LastIndex(v, "=")
	if i <= 0 {
		return errors.New("format attendu : CLÉPUBLIQUE=IP")
	}
	k, ip := v[:i], v[i+1:]
	key, err := vpn.ParseKey(k)
	if err != nil {
		return err
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return fmt.Errorf("adresse %q invalide", ip)
	}
	*l = append(*l, vpn.PeerConfig{PublicKey: key, Address: addr})
	return nil
}

func cmdServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	keyPath := fs.String("key", "server.key", "clé privée du serveur")
	listen := fs.String("listen", ":51820", "adresse et port UDP d'écoute")
	addr := fs.String("addr", "10.8.0.1/24", "adresse du serveur dans le tunnel, avec le réseau du tunnel")
	devName := fs.String("dev", "", "nom de l'interface (Linux uniquement)")
	verbose := fs.Bool("v", false, "journal détaillé")
	var peers peerList
	fs.Var(&peers, "peer", "client autorisé, au format CLÉPUBLIQUE=IP (répétable)")
	fs.Parse(args)

	priv, err := vpn.LoadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(*addr)
	if err != nil {
		return fmt.Errorf("-addr : %w", err)
	}
	laddr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		return fmt.Errorf("-listen : %w", err)
	}
	if err := requireRoot(); err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return err
	}
	dev, err := tun.Create(*devName)
	if err != nil {
		conn.Close()
		return err
	}
	logger := log.New(os.Stderr, "", log.LstdFlags)
	node, err := vpn.NewServer(vpn.ServerConfig{PrivateKey: priv, Address: prefix, Peers: peers}, conn, dev, logger, *verbose)
	if err == nil {
		err = netcfg.Configure(dev.Name(), prefix, vpn.TunnelMTU)
	}
	if err != nil {
		dev.Close()
		conn.Close()
		return err
	}
	logger.Printf("serveur à l'écoute sur %s (UDP), interface %s = %s, %d client(s) autorisé(s)", conn.LocalAddr(), dev.Name(), prefix, len(peers))
	logger.Printf("clé publique du serveur : %s", node.PublicKey())
	return runUntilSignal(node)
}

func cmdClient(args []string) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	keyPath := fs.String("key", "client.key", "clé privée du client")
	server := fs.String("server", "", "adresse du serveur, ex. 203.0.113.10:51820")
	serverKey := fs.String("server-key", "", "clé publique du serveur")
	addr := fs.String("addr", "10.8.0.2/24", "adresse du client dans le tunnel, avec le réseau du tunnel")
	devName := fs.String("dev", "", "nom de l'interface (Linux uniquement)")
	verbose := fs.Bool("v", false, "journal détaillé")
	fs.Parse(args)

	if *server == "" || *serverKey == "" {
		return errors.New("-server et -server-key sont obligatoires")
	}
	priv, err := vpn.LoadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	skey, err := vpn.ParseKey(*serverKey)
	if err != nil {
		return fmt.Errorf("-server-key : %w", err)
	}
	prefix, err := netip.ParsePrefix(*addr)
	if err != nil {
		return fmt.Errorf("-addr : %w", err)
	}
	raddr, err := net.ResolveUDPAddr("udp", *server)
	if err != nil {
		return fmt.Errorf("-server : %w", err)
	}
	ap := raddr.AddrPort()
	ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	if err := requireRoot(); err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return err
	}
	dev, err := tun.Create(*devName)
	if err != nil {
		conn.Close()
		return err
	}
	logger := log.New(os.Stderr, "", log.LstdFlags)
	node, err := vpn.NewClient(vpn.ClientConfig{PrivateKey: priv, Address: prefix, Server: ap, ServerKey: skey}, conn, dev, logger, *verbose)
	if err == nil {
		err = netcfg.Configure(dev.Name(), prefix, vpn.TunnelMTU)
	}
	if err != nil {
		dev.Close()
		conn.Close()
		return err
	}
	logger.Printf("client : interface %s = %s, connexion à %s…", dev.Name(), prefix, ap)
	return runUntilSignal(node)
}

func runUntilSignal(node *vpn.Node) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := node.Run(ctx)
	fmt.Fprintln(os.Stderr, "arrêt : interface et routes supprimées")
	return err
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("créer une interface réseau demande les droits administrateur : relance avec sudo")
	}
	return nil
}

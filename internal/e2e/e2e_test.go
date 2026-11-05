//go:build e2e && linux

// Test de bout en bout avec une vraie interface réseau (Linux, root) :
//
//	sudo MINIVPN_BIN=$PWD/minivpn go test -tags e2e ./internal/e2e/ -v
//
// Le vrai binaire « minivpn server » crée minivpnN = 10.8.0.1/24. Un client (ce test) se
// connecte en UDP sur 127.0.0.1 et envoie un ping puis un message UDP dans le tunnel :
// c'est le noyau Linux du « serveur » qui répond. Pendant ce temps, une capture brute sur
// l'interface loopback vérifie qu'aucun contenu ne circule en clair.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/manthole/minivpn/internal/vpn"
	"golang.org/x/sys/unix"
)

const (
	serverPort = 51899
	secret     = "message tres secret dans le tunnel"
)

type chanDev struct {
	in, out chan []byte
	done    chan struct{}
	once    sync.Once
}

func (d *chanDev) Read(p []byte) (int, error) {
	select {
	case pkt := <-d.in:
		return copy(p, pkt), nil
	case <-d.done:
		return 0, os.ErrClosed
	}
}
func (d *chanDev) Write(p []byte) (int, error) {
	select {
	case d.out <- append([]byte(nil), p...):
		return len(p), nil
	case <-d.done:
		return 0, os.ErrClosed
	}
}
func (d *chanDev) Close() error { d.once.Do(func() { close(d.done) }); return nil }

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func ipPacket(proto byte, src, dst string, body []byte) []byte {
	pkt := make([]byte, 20+len(body))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	pkt[8], pkt[9] = 64, proto
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	binary.BigEndian.PutUint16(pkt[10:], checksum(pkt[:20]))
	copy(pkt[20:], body)
	return pkt
}

func genkey(t *testing.T, bin, path string) vpn.Key {
	t.Helper()
	out, err := exec.Command(bin, "genkey", "-out", path).Output()
	if err != nil {
		t.Fatalf("genkey : %v", err)
	}
	k, err := vpn.ParseKey(string(out))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// sniff capture toutes les trames de l'interface loopback (comme tcpdump -i lo).
func sniff(t *testing.T, stop <-chan struct{}) <-chan [][]byte {
	t.Helper()
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		t.Fatalf("capture impossible : %v", err)
	}
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: lo.Index}); err != nil {
		t.Fatal(err)
	}
	tv := unix.Timeval{Usec: 100000}
	unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	res := make(chan [][]byte, 1)
	go func() {
		defer unix.Close(fd)
		var frames [][]byte
		buf := make([]byte, 65536)
		for {
			select {
			case <-stop:
				res <- frames
				return
			default:
			}
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err == nil && n > 0 {
				frames = append(frames, append([]byte(nil), buf[:n]...))
			}
		}
	}()
	return res
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func TestRealTunnel(t *testing.T) {
	bin := os.Getenv("MINIVPN_BIN")
	if bin == "" || os.Geteuid() != 0 {
		t.Skip("lancer en root avec MINIVPN_BIN=chemin/vers/minivpn")
	}
	dir := t.TempDir()
	srvPub := genkey(t, bin, filepath.Join(dir, "server.key"))
	cliPub := genkey(t, bin, filepath.Join(dir, "client.key"))
	cliPriv, err := vpn.LoadPrivateKey(filepath.Join(dir, "client.key"))
	if err != nil {
		t.Fatal(err)
	}

	// 1. le vrai serveur
	srv := exec.Command(bin, "server", "-key", filepath.Join(dir, "server.key"),
		"-listen", "127.0.0.1:51899", "-addr", "10.8.0.1/24", "-peer", cliPub.String()+"=10.8.0.2")
	stderr, _ := srv.StderrPipe()
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	var srvLog bytes.Buffer
	var logMu sync.Mutex
	ready := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stderr)
		re := regexp.MustCompile(`interface (\S+) = `)
		for sc.Scan() {
			logMu.Lock()
			srvLog.WriteString(sc.Text() + "\n")
			logMu.Unlock()
			if m := re.FindStringSubmatch(sc.Text()); m != nil {
				ready <- m[1]
			}
		}
	}()
	var ifname string
	select {
	case ifname = <-ready:
	case <-time.After(5 * time.Second):
		t.Fatalf("le serveur n'a pas démarré :\n%s", srvLog.String())
	}
	defer func() {
		srv.Process.Signal(syscall.SIGTERM)
		srv.Wait()
		if _, err := net.InterfaceByName(ifname); err == nil {
			t.Errorf("l'interface %s existe encore après l'arrêt", ifname)
		} else {
			t.Logf("arrêt propre : %s supprimée", ifname)
		}
		logMu.Lock()
		t.Logf("journal du serveur :\n%s", srvLog.String())
		logMu.Unlock()
	}()

	// 2. l'interface créée par le serveur
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		t.Fatal(err)
	}
	addrs, _ := iface.Addrs()
	t.Logf("interface %s : MTU %d, drapeaux %v, adresses %v", ifname, iface.MTU, iface.Flags, addrs)
	if iface.MTU != vpn.TunnelMTU || iface.Flags&net.FlagUp == 0 || len(addrs) == 0 || addrs[0].String() != "10.8.0.1/24" {
		t.Fatal("interface mal configurée")
	}

	// 3. un service UDP qui écoute sur l'adresse du tunnel, côté serveur
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(10, 8, 0, 1), Port: 9999})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	received := make(chan string, 1)
	go func() {
		buf := make([]byte, 2048)
		n, from, err := echo.ReadFromUDP(buf)
		if err != nil {
			return
		}
		received <- from.String() + " " + string(buf[:n])
		echo.WriteToUDP([]byte("écho : "+string(buf[:n])), from)
	}()

	// 4. l'espion sur le réseau + le client
	stopSniff := make(chan struct{})
	captured := sniff(t, stopSniff)
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	dev := &chanDev{in: make(chan []byte, 16), out: make(chan []byte, 16), done: make(chan struct{})}
	cli, err := vpn.NewClient(vpn.ClientConfig{PrivateKey: cliPriv, Address: netip.MustParsePrefix("10.8.0.2/24"),
		Server: netip.MustParseAddrPort("127.0.0.1:51899"), ServerKey: srvPub}, conn, dev, log.New(io.Discard, "", 0), false)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- cli.Run(ctx) }()
	defer func() { cancel(); <-done }()

	await := func(what string, match func([]byte) bool) []byte {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for {
			select {
			case pkt := <-dev.out:
				if match(pkt) {
					return pkt
				}
			case <-deadline:
				t.Fatalf("%s : pas de réponse", what)
			}
		}
	}

	// 5. ping 10.8.0.1 : la réponse vient du noyau Linux, à travers le tunnel
	icmp := []byte{8, 0, 0, 0, 0x12, 0x34, 0, 1}
	icmp = append(icmp, []byte("minivpn-ping")...)
	binary.BigEndian.PutUint16(icmp[2:], checksum(icmp))
	start := time.Now()
	dev.in <- ipPacket(1, "10.8.0.2", "10.8.0.1", icmp)
	reply := await("ping", func(p []byte) bool { return len(p) > 28 && p[9] == 1 && p[20] == 0 })
	if !bytes.Equal(reply[24:26], []byte{0x12, 0x34}) || !bytes.Contains(reply, []byte("minivpn-ping")) {
		t.Fatal("réponse ICMP inattendue")
	}
	t.Logf("ping 10.8.0.1 : réponse du noyau en %v (poignée de main comprise)", time.Since(start).Round(time.Microsecond))

	// 6. un vrai échange UDP avec une application côté serveur
	udp := make([]byte, 8+len(secret))
	binary.BigEndian.PutUint16(udp[0:], 40000)
	binary.BigEndian.PutUint16(udp[2:], 9999)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp))) // somme de contrôle UDP à 0 : autorisé en IPv4
	copy(udp[8:], secret)
	dev.in <- ipPacket(17, "10.8.0.2", "10.8.0.1", udp)
	select {
	case got := <-received:
		t.Logf("l'application du serveur a reçu : %q", got)
		if !strings.HasPrefix(got, "10.8.0.2:40000 ") {
			t.Fatalf("adresse source inattendue : %s", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("le service UDP n'a rien reçu")
	}
	back := await("réponse UDP", func(p []byte) bool { return len(p) > 28 && p[9] == 17 })
	t.Logf("le client a reçu : %q", back[28:])

	// 7. ce qu'a vu l'espion
	time.Sleep(200 * time.Millisecond)
	close(stopSniff)
	frames := <-captured
	tunnelFrames := 0
	port := []byte{serverPort >> 8, serverPort & 0xff}
	for _, f := range frames {
		if bytes.Contains(f, []byte(secret)) && bytes.Contains(f, port) {
			t.Fatal("le message secret circule EN CLAIR entre client et serveur !")
		}
		if bytes.Contains(f, port) {
			tunnelFrames++
		}
	}
	if tunnelFrames == 0 {
		t.Fatal("la capture n'a rien vu passer (test invalide)")
	}
	t.Logf("capture réseau : %d trames du tunnel, aucune ne contient le message en clair", tunnelFrames)
}

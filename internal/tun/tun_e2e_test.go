//go:build e2e && (linux || darwin)

// Test réel de l'interface virtuelle (root) : sudo go test -tags e2e ./internal/tun/
//
// On crée l'interface, on lui donne 10.77.0.2/24, puis :
//  1. une application envoie un datagramme UDP vers 10.77.0.1 : le système le route dans
//     l'interface, et Read doit le renvoyer ;
//  2. on injecte une réponse avec Write : le système doit la livrer à l'application.
//
// Sur macOS, cela vérifie la partie utun (en-tête de 4 octets, ifconfig, route).
package tun_test

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/manthole/minivpn/internal/netcfg"
	"github.com/manthole/minivpn/internal/tun"
)

func ipChecksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func TestDeviceRoundTrip(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("demande les droits root")
	}
	dev, err := tun.Create("")
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	if err := netcfg.Configure(dev.Name(), netip.MustParsePrefix("10.77.0.2/24"), 1420); err != nil {
		t.Fatal(err)
	}
	t.Logf("interface %s configurée", dev.Name())

	app, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(10, 77, 0, 2)})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	appPort := app.LocalAddr().(*net.UDPAddr).Port

	// 1. application → interface
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := dev.Read(buf)
			if err != nil {
				return
			}
			p := buf[:n]
			if len(p) >= 28 && p[0]>>4 == 4 && p[9] == 17 && binary.BigEndian.Uint16(p[22:24]) == 9999 {
				got <- append([]byte(nil), p...)
				return
			}
		}
	}()
	time.Sleep(200 * time.Millisecond) // laisse le système finir de configurer l'interface
	if _, err := app.WriteToUDP([]byte("vers le tunnel"), &net.UDPAddr{IP: net.IPv4(10, 77, 0, 1), Port: 9999}); err != nil {
		t.Fatal(err)
	}
	var pkt []byte
	select {
	case pkt = <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("le paquet n'est pas sorti par l'interface (route ou lecture défaillante)")
	}
	ihl := int(pkt[0]&0x0f) * 4
	if src := netip.AddrFrom4([4]byte(pkt[12:16])); src.String() != "10.77.0.2" {
		t.Fatalf("source inattendue : %s", src)
	}
	if string(pkt[ihl+8:]) != "vers le tunnel" {
		t.Fatalf("contenu inattendu : %q", pkt[ihl+8:])
	}
	t.Logf("lu sur l'interface : %d octets, de 10.77.0.2:%d vers 10.77.0.1:9999", len(pkt), appPort)

	// 2. interface → application
	payload := []byte("depuis le tunnel")
	reply := make([]byte, 28+len(payload))
	reply[0] = 0x45
	binary.BigEndian.PutUint16(reply[2:], uint16(len(reply)))
	reply[8], reply[9] = 64, 17
	copy(reply[12:16], []byte{10, 77, 0, 1})
	copy(reply[16:20], []byte{10, 77, 0, 2})
	binary.BigEndian.PutUint16(reply[10:], ipChecksum(reply[:20]))
	binary.BigEndian.PutUint16(reply[20:], 9999)
	binary.BigEndian.PutUint16(reply[22:], uint16(appPort))
	binary.BigEndian.PutUint16(reply[24:], uint16(8+len(payload))) // somme de contrôle UDP à 0 : autorisé en IPv4
	copy(reply[28:], payload)
	if _, err := dev.Write(reply); err != nil {
		t.Fatal(err)
	}
	app.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, from, err := app.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("la réponse injectée n'a pas été livrée : %v", err)
	}
	if string(buf[:n]) != string(payload) || from.String() != "10.77.0.1:9999" {
		t.Fatalf("réponse inattendue : %q de %s", buf[:n], from)
	}
	t.Logf("réponse injectée reçue par l'application : %q de %s", buf[:n], from)
}

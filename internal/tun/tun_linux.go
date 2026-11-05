//go:build linux

// Package tun crée l'interface réseau virtuelle par laquelle le système envoie et reçoit
// les paquets du tunnel.
package tun

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Device : une interface TUN. Chaque Read renvoie un paquet IP complet.
type Device struct {
	f    *os.File
	name string
}

// Create ouvre /dev/net/tun et crée une interface. Un nom vide laisse le noyau choisir
// (minivpn0, minivpn1…). L'interface disparaît à la fermeture.
func Create(name string) (*Device, error) {
	if name == "" {
		name = "minivpn%d"
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("ouverture de /dev/net/tun : %w (faut-il lancer avec sudo ?)", err)
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	// IFF_TUN : paquets IP (pas de trames Ethernet) ; IFF_NO_PI : sans en-tête supplémentaire.
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("création de l'interface : %w", err)
	}
	// non bloquant : Go peut alors interrompre la lecture proprement à la fermeture
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &Device{f: os.NewFile(uintptr(fd), "/dev/net/tun"), name: ifr.Name()}, nil
}

func (d *Device) Name() string                { return d.name }
func (d *Device) Read(p []byte) (int, error)  { return d.f.Read(p) }
func (d *Device) Write(p []byte) (int, error) { return d.f.Write(p) }
func (d *Device) Close() error                { return d.f.Close() }

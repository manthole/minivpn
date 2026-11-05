//go:build linux

// Package netcfg attribue l'adresse du tunnel à l'interface et l'active.
package netcfg

import (
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

// Configure fait l'équivalent de :
//
//	ip addr add 10.8.0.2/24 dev minivpn0
//	ip link set dev minivpn0 mtu 1420 up
//
// directement par appels système (ioctl), sans dépendre de la commande « ip ».
// Le noyau ajoute alors tout seul la route vers le réseau du tunnel (10.8.0.0/24).
func Configure(dev string, addr netip.Prefix, mtu int) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	set := func(what string, req uint, fill func(*unix.Ifreq) error) error {
		ifr, err := unix.NewIfreq(dev)
		if err != nil {
			return err
		}
		if err := fill(ifr); err != nil {
			return err
		}
		if err := unix.IoctlIfreq(fd, req, ifr); err != nil {
			return fmt.Errorf("%s de %s : %w", what, dev, err)
		}
		return nil
	}
	ip := addr.Addr().As4()
	mask := net.CIDRMask(addr.Bits(), 32)
	if err := set("adresse", unix.SIOCSIFADDR, func(r *unix.Ifreq) error { return r.SetInet4Addr(ip[:]) }); err != nil {
		return err
	}
	if err := set("masque", unix.SIOCSIFNETMASK, func(r *unix.Ifreq) error { return r.SetInet4Addr(mask) }); err != nil {
		return err
	}
	if err := set("MTU", unix.SIOCSIFMTU, func(r *unix.Ifreq) error { r.SetUint32(uint32(mtu)); return nil }); err != nil {
		return err
	}
	// activation : on lit les drapeaux actuels puis on ajoute UP
	ifr, err := unix.NewIfreq(dev)
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("lecture des drapeaux de %s : %w", dev, err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP | unix.IFF_RUNNING)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("activation de %s : %w", dev, err)
	}
	return nil
}

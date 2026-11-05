//go:build darwin

package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// Sur macOS, l'interface virtuelle s'appelle utunN. On l'obtient en ouvrant une socket
// « système » vers le contrôleur noyau com.apple.net.utun_control. Chaque paquet y est
// précédé de 4 octets indiquant la famille d'adresses (AF_INET ou AF_INET6).
const (
	utunControlName = "com.apple.net.utun_control"
	sysprotoControl = 2 // SYSPROTO_CONTROL
	utunOptIfname   = 2 // UTUN_OPT_IFNAME
)

type Device struct {
	f    *os.File
	name string

	rmu, wmu   sync.Mutex
	rbuf, wbuf []byte
}

// Create crée une interface utun. Le nom est choisi par le système (utun0, utun1…) :
// le paramètre est ignoré sur macOS.
func Create(_ string) (*Device, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, fmt.Errorf("socket utun : %w (faut-il lancer avec sudo ?)", err)
	}
	info := &unix.CtlInfo{}
	copy(info.Name[:], utunControlName)
	if err := unix.IoctlCtlInfo(fd, info); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("contrôleur utun introuvable : %w", err)
	}
	// Unit 0 : le noyau attribue le premier numéro libre
	if err := unix.Connect(fd, &unix.SockaddrCtl{ID: info.Id, Unit: 0}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("création de l'interface utun : %w (faut-il lancer avec sudo ?)", err)
	}
	name, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfname)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &Device{
		f:    os.NewFile(uintptr(fd), name),
		name: name,
		rbuf: make([]byte, 65535+4),
		wbuf: make([]byte, 65535+4),
	}, nil
}

func (d *Device) Name() string { return d.name }

func (d *Device) Read(p []byte) (int, error) {
	d.rmu.Lock()
	defer d.rmu.Unlock()
	for {
		n, err := d.f.Read(d.rbuf)
		if err != nil {
			return 0, err
		}
		if n <= 4 {
			continue
		}
		return copy(p, d.rbuf[4:n]), nil
	}
}

func (d *Device) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	var family uint32
	switch p[0] >> 4 {
	case 4:
		family = unix.AF_INET
	case 6:
		family = unix.AF_INET6
	default:
		return 0, errors.New("paquet IP invalide")
	}
	d.wmu.Lock()
	defer d.wmu.Unlock()
	if len(p)+4 > len(d.wbuf) {
		return 0, errors.New("paquet trop grand")
	}
	binary.BigEndian.PutUint32(d.wbuf[:4], family)
	n := copy(d.wbuf[4:], p)
	if _, err := d.f.Write(d.wbuf[:4+n]); err != nil {
		return 0, err
	}
	return n, nil
}

func (d *Device) Close() error { return d.f.Close() }

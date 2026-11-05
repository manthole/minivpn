//go:build darwin

package netcfg

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Configure, comme le fait wg-quick sur macOS :
//
//	ifconfig utun5 inet 10.8.0.2/24 10.8.0.2 alias
//	ifconfig utun5 mtu 1420 up
//	route -q -n add -inet 10.8.0.0/24 -interface utun5
//
// Tout disparaît automatiquement quand le programme ferme l'interface.
func Configure(dev string, addr netip.Prefix, mtu int) error {
	local := addr.Addr().String()
	if err := run("ifconfig", dev, "inet", addr.String(), local, "alias"); err != nil {
		return err
	}
	if err := run("ifconfig", dev, "mtu", strconv.Itoa(mtu), "up"); err != nil {
		return err
	}
	err := run("route", "-q", "-n", "add", "-inet", addr.Masked().String(), "-interface", dev)
	if err != nil && strings.Contains(err.Error(), "File exists") {
		// route déjà présente (ajoutée par le système, ou par un autre VPN) : on continue
		fmt.Fprintf(os.Stderr, "attention : une route vers %s existait déjà ; si le tunnel ne répond pas, un autre VPN utilise peut-être ce réseau\n", addr.Masked())
		return nil
	}
	return err
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s : %v %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

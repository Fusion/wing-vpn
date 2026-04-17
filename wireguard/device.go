package wireguard

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
)

func DeviceExists(name string) bool {
	client, err := wgctrl.New()
	if err != nil {
		return false
	}
	defer client.Close()
	_, err = client.Device(name)
	return err == nil
}

func EnsureUserspaceWG(iface, explicitPath string, detach bool) (string, *exec.Cmd, error) {
	wgPath, err := findWireguardGo(explicitPath)
	if err != nil {
		return "", nil, err
	}

	var utunsBefore map[string]struct{}
	if runtime.GOOS == "darwin" {
		utunsBefore = listDarwinUtuns()
	}

	cmd := exec.Command(wgPath, iface)
	if detach {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return "", nil, err
	}

	switch runtime.GOOS {
	case "linux":
		if err := waitForIfaceLinux(iface, 3*time.Second); err != nil {
			return "", cmd, err
		}
		return iface, cmd, nil

	case "darwin":
		osIface, err := waitForNewUtun(utunsBefore, 3*time.Second)
		if err != nil {
			return "", cmd, err
		}
		return osIface, cmd, nil

	default:
		return "", cmd, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func EnsureLinuxDevice(iface, explicitPath string, detach bool) (string, *exec.Cmd, bool, error) {
	if err := tryKernelInterface(iface); err == nil {
		return iface, nil, true, nil
	}
	osIface, cmd, err := EnsureUserspaceWG(iface, explicitPath, detach)
	if err == nil {
		return osIface, cmd, false, nil
	}
	return "", nil, false, fmt.Errorf("kernel WireGuard not available; userspace failed: %v", err)
}

func tryKernelInterface(iface string) error {
	out, err := exec.Command("ip", "link", "add", "dev", iface, "type", "wireguard").CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

func findWireguardGo(explicitPath string) (string, error) {
	if explicitPath != "" {
		if st, err := os.Stat(explicitPath); err == nil && !st.IsDir() {
			return explicitPath, nil
		}
		return "", fmt.Errorf("wireguard-go not found at %s", explicitPath)
	}

	// Some distros ship userspace WireGuard as "wireguard", so treat it as an alias.
	if p, err := exec.LookPath("wireguard-go"); err == nil {
		return p, nil
	}
	if p, err := exec.LookPath("wireguard"); err == nil {
		return p, nil
	}

	candidates := []string{
		"/usr/bin/wireguard-go",
		"/usr/sbin/wireguard-go",
		"/usr/local/bin/wireguard-go",
		"/sbin/wireguard-go",
		"/bin/wireguard-go",
		"/opt/homebrew/bin/wireguard-go",
		"/usr/bin/wireguard",
		"/usr/sbin/wireguard",
		"/usr/local/bin/wireguard",
		"/sbin/wireguard",
		"/bin/wireguard",
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, nil
		}
	}
	return "", fmt.Errorf("wireguard-go not found in PATH; install it or pass -wireguard-go /path/to/wireguard-go (or wireguard)")
}

func waitForIfaceLinux(iface string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if exec.Command("ip", "link", "show", iface).Run() == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("interface %s not ready", iface)
}

func listDarwinUtuns() map[string]struct{} {
	utuns := make(map[string]struct{})
	out, err := exec.Command("ifconfig", "-l").Output()
	if err != nil {
		return utuns
	}
	fields := strings.Fields(string(out))
	for _, f := range fields {
		if strings.HasPrefix(f, "utun") {
			utuns[f] = struct{}{}
		}
	}
	return utuns
}

func darwinUtunExists(name string) bool {
	if !strings.HasPrefix(name, "utun") {
		return false
	}
	utuns := listDarwinUtuns()
	_, ok := utuns[name]
	return ok
}

func waitForNewUtun(before map[string]struct{}, timeout time.Duration) (string, error) {
	// On macOS, wireguard-go creates a new utun with a dynamic name; detect the delta.
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		after := listDarwinUtuns()
		var newOnes []string
		for name := range after {
			if _, ok := before[name]; !ok {
				newOnes = append(newOnes, name)
			}
		}
		if len(newOnes) == 1 {
			return newOnes[0], nil
		}
		if len(newOnes) > 1 {
			return "", fmt.Errorf("multiple new utun interfaces detected: %v", newOnes)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return "", errors.New("utun interface not ready")
}

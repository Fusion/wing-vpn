package wireguard

import (
	"fmt"
	"net"
	"os"
	"os/exec"
)

func run(cmd string, args ...string) error {
	c := exec.Command(cmd, args...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

func RunCommand(cmd string, args ...string) error {
	return run(cmd, args...)
}

func maskToDotted(mask net.IPMask) string {
	if len(mask) != 4 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}

package main

import (
	"os/exec"
	"runtime"

	"wing/config"
	"wing/wireguard"
)

type session struct {
	config        *config.Config
	osIface       string
	wgCmd         *exec.Cmd
	routesAdded   bool
	deleteOnExit  bool
	createdByWing bool
}

func startSession(cfg *config.Config, wgGoPath string, reuse bool, detach bool) (*session, error) {
	if err := config.EnsureRuntimeIdentity(cfg); err != nil {
		return nil, err
	}
	if reuse && runtime.GOOS == "darwin" {
		return nil, errString("-reuse is not supported on macOS; stop the existing device first")
	}
	if wireguard.DeviceExists(cfg.Interface) && !reuse {
		return nil, errString("device " + cfg.Interface + " already exists; use -reuse (linux only) or pick a different interface")
	}

	s := &session{config: cfg}
	osIface := cfg.Interface
	if !wireguard.DeviceExists(cfg.Interface) {
		if runtime.GOOS == "linux" {
			var createdKernel bool
			var err error
			osIface, s.wgCmd, createdKernel, err = wireguard.EnsureLinuxDevice(cfg.Interface, wgGoPath, detach)
			if err != nil {
				return nil, err
			}
			s.deleteOnExit = createdKernel
			s.createdByWing = createdKernel || s.wgCmd != nil
		} else {
			var err error
			osIface, s.wgCmd, err = wireguard.EnsureUserspaceWG(cfg.Interface, wgGoPath, detach)
			if err != nil {
				return nil, err
			}
			s.createdByWing = s.wgCmd != nil
		}
	}
	s.osIface = osIface
	if err := wireguard.SetInterfaceAddr(s.osIface, cfg.Address, cfg.MTU); err != nil {
		return nil, err
	}
	if err := wireguard.Configure(cfg); err != nil {
		return nil, err
	}
	if !cfg.DisableRoutes {
		if err := wireguard.AddPeerRoutes(s.osIface, cfg.Peers); err != nil {
			return nil, err
		}
		s.routesAdded = true
	}
	if s.createdByWing {
		if err := config.WriteState(cfg, s.osIface); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *session) cleanup() {
	if s == nil {
		return
	}
	if s.routesAdded {
		wireguard.RemovePeerRoutes(s.osIface, s.config.Peers)
	}
	if s.deleteOnExit && runtime.GOOS == "linux" {
		_ = wireguard.RunCommand("ip", "link", "del", s.osIface)
	}
	if s.wgCmd != nil && s.wgCmd.Process != nil {
		_ = s.wgCmd.Process.Kill()
		_, _ = s.wgCmd.Process.Wait()
	}
	_ = config.RemoveState(s.config.Interface)
}

type errString string

func (e errString) Error() string { return string(e) }

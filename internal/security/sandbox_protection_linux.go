//go:build linux

package security

import (
	"os/exec"
	"syscall"
)

// applyLinuxRestrictions applies Linux-specific restrictions using namespaces and cgroups
func (sp *SandboxProtection) applyLinuxRestrictions(cmd *exec.Cmd) error {
	// Use Linux namespaces for isolation
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET,
		Setpgid:    true,
	}

	return nil
}

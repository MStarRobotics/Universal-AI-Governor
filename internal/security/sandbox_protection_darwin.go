//go:build darwin

package security

import (
	"os/exec"
)

// applyLinuxRestrictions is a no-op on macOS
func (sp *SandboxProtection) applyLinuxRestrictions(cmd *exec.Cmd) error {
	// macOS doesn't support Linux namespaces
	return nil
}

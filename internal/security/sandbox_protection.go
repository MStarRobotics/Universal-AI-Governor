package security

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/universal-ai-governor/internal/logging"
)

// SandboxProtection implements process isolation and sandboxing
type SandboxProtection struct {
	logger           logging.Logger
	sandboxEnabled   bool
	quarantineDir    string
	backupDir        string
	processLimits    *ProcessLimits
	networkPolicy    *NetworkPolicy
	fileSystemPolicy *FileSystemPolicy
}

// ProcessLimits defines resource limits for sandboxed processes
type ProcessLimits struct {
	MaxMemoryMB     int           `json:"max_memory_mb"`
	MaxCPUPercent   int           `json:"max_cpu_percent"`
	MaxFileHandles  int           `json:"max_file_handles"`
	MaxProcesses    int           `json:"max_processes"`
	MaxExecutionTime time.Duration `json:"max_execution_time"`
	AllowedSyscalls []string      `json:"allowed_syscalls"`
}

// NetworkPolicy defines network access restrictions
type NetworkPolicy struct {
	AllowOutbound    bool     `json:"allow_outbound"`
	AllowedHosts     []string `json:"allowed_hosts"`
	AllowedPorts     []int    `json:"allowed_ports"`
	BlockedProtocols []string `json:"blocked_protocols"`
	DNSRestrictions  bool     `json:"dns_restrictions"`
}

// FileSystemPolicy defines file system access restrictions
type FileSystemPolicy struct {
	ReadOnlyPaths    []string `json:"readonly_paths"`
	ReadWritePaths   []string `json:"readwrite_paths"`
	BlockedPaths     []string `json:"blocked_paths"`
	TempDirOnly      bool     `json:"temp_dir_only"`
	NoExecPaths      []string `json:"no_exec_paths"`
}

// SandboxedProcess represents a process running in a sandbox
type SandboxedProcess struct {
	PID           int                    `json:"pid"`
	Command       string                 `json:"command"`
	Args          []string               `json:"args"`
	StartTime     time.Time              `json:"start_time"`
	Limits        *ProcessLimits         `json:"limits"`
	Status        string                 `json:"status"`
	ResourceUsage map[string]interface{} `json:"resource_usage"`
	Violations    []string               `json:"violations"`
}

// QuarantineEntry represents a quarantined file or process
type QuarantineEntry struct {
	ID            string                 `json:"id"`
	Type          string                 `json:"type"` // "file", "process", "binary"
	OriginalPath  string                 `json:"original_path"`
	QuarantinePath string                `json:"quarantine_path"`
	Reason        string                 `json:"reason"`
	ThreatLevel   int                    `json:"threat_level"`
	Metadata      map[string]interface{} `json:"metadata"`
	QuarantinedAt time.Time              `json:"quarantined_at"`
	Restored      bool                   `json:"restored"`
	RestoredAt    time.Time              `json:"restored_at"`
}

// NewSandboxProtection creates a new sandbox protection system
func NewSandboxProtection(logger logging.Logger) (*SandboxProtection, error) {
	sp := &SandboxProtection{
		logger:        logger,
		sandboxEnabled: true,
		quarantineDir: "/var/quarantine/ai-governor",
		backupDir:     "/var/backup/ai-governor",
	}

	// Initialize default policies based on platform
	if err := sp.initializePlatformSpecificPolicies(); err != nil {
		return nil, fmt.Errorf("failed to initialize platform policies: %w", err)
	}

	// Create necessary directories
	if err := sp.createDirectories(); err != nil {
		return nil, fmt.Errorf("failed to create directories: %w", err)
	}

	logger.Info("Sandbox protection initialized",
		"platform", runtime.GOOS,
		"quarantine_dir", sp.quarantineDir,
		"backup_dir", sp.backupDir)

	return sp, nil
}

// initializePlatformSpecificPolicies sets up platform-specific sandbox policies
func (sp *SandboxProtection) initializePlatformSpecificPolicies() error {
	switch runtime.GOOS {
	case "darwin":
		return sp.initializeMacOSSandbox()
	case "linux":
		return sp.initializeLinuxSandbox()
	case "windows":
		return sp.initializeWindowsSandbox()
	default:
		return sp.initializeGenericSandbox()
	}
}

// initializeMacOSSandbox sets up macOS-specific sandbox policies
func (sp *SandboxProtection) initializeMacOSSandbox() error {
	sp.logger.Info("Initializing macOS sandbox policies")

	sp.processLimits = &ProcessLimits{
		MaxMemoryMB:      1024,
		MaxCPUPercent:    50,
		MaxFileHandles:   256,
		MaxProcesses:     10,
		MaxExecutionTime: 30 * time.Minute,
		AllowedSyscalls: []string{
			"read", "write", "open", "close", "mmap", "munmap",
			"getpid", "getuid", "getgid", "exit", "sigaction",
		},
	}

	sp.networkPolicy = &NetworkPolicy{
		AllowOutbound: true,
		AllowedHosts: []string{
			"api.openai.com",
			"api.anthropic.com",
			"localhost",
			"127.0.0.1",
		},
		AllowedPorts:     []int{80, 443, 8080, 11434},
		BlockedProtocols: []string{"ftp", "telnet", "ssh"},
		DNSRestrictions:  true,
	}

	sp.fileSystemPolicy = &FileSystemPolicy{
		ReadOnlyPaths: []string{
			"/usr/local/bin/ai-governor",
			"/etc/ai-governor/policies",
			"/System",
			"/usr/bin",
			"/bin",
		},
		ReadWritePaths: []string{
			"/tmp/ai-governor",
			"/var/log/ai-governor",
			"/var/lib/ai-governor",
		},
		BlockedPaths: []string{
			"/etc/passwd",
			"/etc/shadow",
			"/root",
			"/Users/*/Documents",
			"/Users/*/Desktop",
		},
		TempDirOnly: false,
		NoExecPaths: []string{
			"/tmp",
			"/var/tmp",
			"/Users/*/Downloads",
		},
	}

	return nil
}

// initializeLinuxSandbox sets up Linux-specific sandbox policies
func (sp *SandboxProtection) initializeLinuxSandbox() error {
	sp.logger.Info("Initializing Linux sandbox policies")

	sp.processLimits = &ProcessLimits{
		MaxMemoryMB:      1024,
		MaxCPUPercent:    50,
		MaxFileHandles:   256,
		MaxProcesses:     10,
		MaxExecutionTime: 30 * time.Minute,
		AllowedSyscalls: []string{
			"read", "write", "openat", "close", "mmap", "munmap",
			"getpid", "getuid", "getgid", "exit_group", "rt_sigaction",
			"brk", "access", "execve", "wait4", "clone",
		},
	}

	sp.networkPolicy = &NetworkPolicy{
		AllowOutbound:    true,
		AllowedHosts:     []string{"api.openai.com", "api.anthropic.com", "localhost"},
		AllowedPorts:     []int{80, 443, 8080, 11434},
		BlockedProtocols: []string{"ftp", "telnet", "ssh"},
		DNSRestrictions:  true,
	}

	sp.fileSystemPolicy = &FileSystemPolicy{
		ReadOnlyPaths: []string{
			"/usr/local/bin/ai-governor",
			"/etc/ai-governor",
			"/usr/bin",
			"/bin",
			"/lib",
			"/lib64",
		},
		ReadWritePaths: []string{
			"/tmp/ai-governor",
			"/var/log/ai-governor",
			"/var/lib/ai-governor",
		},
		BlockedPaths: []string{
			"/etc/passwd",
			"/etc/shadow",
			"/root",
			"/home/*/Documents",
			"/home/*/Desktop",
		},
		TempDirOnly: false,
		NoExecPaths: []string{
			"/tmp",
			"/var/tmp",
			"/home/*/Downloads",
		},
	}

	return nil
}

// initializeWindowsSandbox sets up Windows-specific sandbox policies
func (sp *SandboxProtection) initializeWindowsSandbox() error {
	sp.logger.Info("Initializing Windows sandbox policies")

	sp.processLimits = &ProcessLimits{
		MaxMemoryMB:      1024,
		MaxCPUPercent:    50,
		MaxFileHandles:   256,
		MaxProcesses:     10,
		MaxExecutionTime: 30 * time.Minute,
	}

	sp.networkPolicy = &NetworkPolicy{
		AllowOutbound:    true,
		AllowedHosts:     []string{"api.openai.com", "api.anthropic.com", "localhost"},
		AllowedPorts:     []int{80, 443, 8080, 11434},
		BlockedProtocols: []string{"ftp", "telnet", "ssh"},
		DNSRestrictions:  true,
	}

	sp.fileSystemPolicy = &FileSystemPolicy{
		ReadOnlyPaths: []string{
			"C:\\Program Files\\AI Governor",
			"C:\\Windows\\System32",
			"C:\\Windows",
		},
		ReadWritePaths: []string{
			"C:\\Temp\\ai-governor",
			"C:\\ProgramData\\AI Governor\\logs",
			"C:\\ProgramData\\AI Governor\\data",
		},
		BlockedPaths: []string{
			"C:\\Users\\*\\Documents",
			"C:\\Users\\*\\Desktop",
			"C:\\Windows\\System32\\config",
		},
		TempDirOnly: false,
		NoExecPaths: []string{
			"C:\\Temp",
			"C:\\Users\\*\\Downloads",
		},
	}

	return nil
}

// initializeGenericSandbox sets up generic sandbox policies
func (sp *SandboxProtection) initializeGenericSandbox() error {
	sp.logger.Info("Initializing generic sandbox policies")

	sp.processLimits = &ProcessLimits{
		MaxMemoryMB:      512,
		MaxCPUPercent:    25,
		MaxFileHandles:   128,
		MaxProcesses:     5,
		MaxExecutionTime: 15 * time.Minute,
	}

	sp.networkPolicy = &NetworkPolicy{
		AllowOutbound:    false,
		AllowedHosts:     []string{"localhost"},
		AllowedPorts:     []int{8080},
		BlockedProtocols: []string{"*"},
		DNSRestrictions:  true,
	}

	sp.fileSystemPolicy = &FileSystemPolicy{
		ReadOnlyPaths:  []string{},
		ReadWritePaths: []string{},
		BlockedPaths:   []string{},
		TempDirOnly:    true,
		NoExecPaths:    []string{"*"},
	}

	return nil
}

// createDirectories creates necessary directories for sandbox operation
func (sp *SandboxProtection) createDirectories() error {
	directories := []string{
		sp.quarantineDir,
		sp.backupDir,
		filepath.Join(sp.quarantineDir, "files"),
		filepath.Join(sp.quarantineDir, "processes"),
		filepath.Join(sp.quarantineDir, "binaries"),
		filepath.Join(sp.backupDir, "configs"),
		filepath.Join(sp.backupDir, "policies"),
		filepath.Join(sp.backupDir, "binaries"),
	}

	for _, dir := range directories {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// CreateSandboxedProcess creates a new process in a sandbox
func (sp *SandboxProtection) CreateSandboxedProcess(command string, args []string) (*SandboxedProcess, error) {
	if !sp.sandboxEnabled {
		return nil, fmt.Errorf("sandbox is disabled")
	}

	sp.logger.Info("Creating sandboxed process",
		"command", command,
		"args", args)

	// Create the process with restrictions
	cmd := exec.Command(command, args...)

	// Apply platform-specific sandbox restrictions
	if err := sp.applySandboxRestrictions(cmd); err != nil {
		return nil, fmt.Errorf("failed to apply sandbox restrictions: %w", err)
	}

	// Start the process
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start sandboxed process: %w", err)
	}

	process := &SandboxedProcess{
		PID:           cmd.Process.Pid,
		Command:       command,
		Args:          args,
		StartTime:     time.Now(),
		Limits:        sp.processLimits,
		Status:        "running",
		ResourceUsage: make(map[string]interface{}),
		Violations:    make([]string, 0),
	}

	// Start monitoring the process
	go sp.monitorSandboxedProcess(process, cmd)

	sp.logger.Info("Sandboxed process created",
		"pid", process.PID,
		"command", command)

	return process, nil
}

// applySandboxRestrictions applies platform-specific sandbox restrictions
func (sp *SandboxProtection) applySandboxRestrictions(cmd *exec.Cmd) error {
	switch runtime.GOOS {
	case "darwin":
		return sp.applyMacOSRestrictions(cmd)
	case "linux":
		return sp.applyLinuxRestrictions(cmd)
	case "windows":
		return sp.applyWindowsRestrictions(cmd)
	default:
		return sp.applyGenericRestrictions(cmd)
	}
}

// applyMacOSRestrictions applies macOS-specific restrictions
func (sp *SandboxProtection) applyMacOSRestrictions(cmd *exec.Cmd) error {
	// Set process attributes for macOS sandbox
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	// Apply resource limits
	// Note: In production, this would use macOS sandbox profiles
	return nil
}

// applyLinuxRestrictions applies Linux-specific restrictions using namespaces and cgroups
func (sp *SandboxProtection) applyLinuxRestrictions(cmd *exec.Cmd) error {
	// Use Linux namespaces for isolation
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET,
		Setpgid:    true,
	}

	// Set resource limits
	// Note: In production, this would integrate with cgroups and seccomp
	return nil
}

// applyWindowsRestrictions applies Windows-specific restrictions
func (sp *SandboxProtection) applyWindowsRestrictions(cmd *exec.Cmd) error {
	// Windows job objects and process restrictions
	// Note: In production, this would use Windows job objects and AppContainer
	return nil
}

// applyGenericRestrictions applies generic restrictions
func (sp *SandboxProtection) applyGenericRestrictions(cmd *exec.Cmd) error {
	// Basic process group isolation
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	return nil
}

// monitorSandboxedProcess monitors a sandboxed process for violations
func (sp *SandboxProtection) monitorSandboxedProcess(process *SandboxedProcess, cmd *exec.Cmd) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check if process is still running
			if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
				process.Status = "exited"
				sp.logger.Info("Sandboxed process exited",
					"pid", process.PID,
					"exit_code", cmd.ProcessState.ExitCode())
				return
			}

			// Monitor resource usage
			if err := sp.checkResourceLimits(process); err != nil {
				sp.logger.Warn("Resource limit violation detected",
					"pid", process.PID,
					"violation", err.Error())
				process.Violations = append(process.Violations, err.Error())

				// Terminate process if critical violation
				if sp.isCriticalViolation(err.Error()) {
					sp.terminateSandboxedProcess(process, cmd)
					return
				}
			}

			// Check execution time limit
			if time.Since(process.StartTime) > process.Limits.MaxExecutionTime {
				sp.logger.Warn("Execution time limit exceeded",
					"pid", process.PID,
					"runtime", time.Since(process.StartTime))
				sp.terminateSandboxedProcess(process, cmd)
				return
			}
		}
	}
}

// checkResourceLimits checks if the process is within resource limits
func (sp *SandboxProtection) checkResourceLimits(process *SandboxedProcess) error {
	// This would check actual resource usage against limits
	// For demonstration, we'll simulate resource monitoring
	
	// In production, this would:
	// 1. Check memory usage via /proc/[pid]/status on Linux
	// 2. Check CPU usage via process statistics
	// 3. Check file handle count
	// 4. Check network connections
	
	return nil
}

// isCriticalViolation determines if a violation requires immediate termination
func (sp *SandboxProtection) isCriticalViolation(violation string) bool {
	criticalViolations := []string{
		"memory_limit_exceeded",
		"unauthorized_file_access",
		"network_policy_violation",
		"syscall_violation",
	}

	for _, critical := range criticalViolations {
		if violation == critical {
			return true
		}
	}

	return false
}

// terminateSandboxedProcess terminates a sandboxed process
func (sp *SandboxProtection) terminateSandboxedProcess(process *SandboxedProcess, cmd *exec.Cmd) {
	sp.logger.Warn("Terminating sandboxed process due to violation",
		"pid", process.PID,
		"violations", process.Violations)

	// Attempt graceful termination first
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		sp.logger.Error("Failed to send SIGTERM", "pid", process.PID, "error", err)
	}

	// Wait for graceful termination
	time.Sleep(5 * time.Second)

	// Force kill if still running
	if cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
		if err := cmd.Process.Kill(); err != nil {
			sp.logger.Error("Failed to kill process", "pid", process.PID, "error", err)
		}
	}

	process.Status = "terminated"
}

// QuarantineFile moves a file to quarantine
func (sp *SandboxProtection) QuarantineFile(filePath, reason string, threatLevel int) (*QuarantineEntry, error) {
	sp.logger.Warn("Quarantining file",
		"file", filePath,
		"reason", reason,
		"threat_level", threatLevel)

	// Generate unique quarantine ID
	quarantineID := generateSecureID()
	quarantinePath := filepath.Join(sp.quarantineDir, "files", quarantineID)

	// Move file to quarantine
	if err := os.Rename(filePath, quarantinePath); err != nil {
		return nil, fmt.Errorf("failed to quarantine file: %w", err)
	}

	entry := &QuarantineEntry{
		ID:             quarantineID,
		Type:           "file",
		OriginalPath:   filePath,
		QuarantinePath: quarantinePath,
		Reason:         reason,
		ThreatLevel:    threatLevel,
		Metadata: map[string]interface{}{
			"file_size": getFileSize(quarantinePath),
			"file_hash": calculateFileHash(quarantinePath),
		},
		QuarantinedAt: time.Now(),
		Restored:      false,
	}

	sp.logger.Info("File quarantined successfully",
		"quarantine_id", quarantineID,
		"original_path", filePath,
		"quarantine_path", quarantinePath)

	return entry, nil
}

// RestoreFromQuarantine restores a quarantined item
func (sp *SandboxProtection) RestoreFromQuarantine(quarantineID string) error {
	// This would restore a quarantined file/process after verification
	sp.logger.Info("Restoring from quarantine", "quarantine_id", quarantineID)
	
	// Implementation would:
	// 1. Verify the item is safe to restore
	// 2. Move it back to original location
	// 3. Update quarantine entry
	
	return nil
}

// AutoRollback performs automatic rollback on integrity failure
func (sp *SandboxProtection) AutoRollback(reason string) error {
	sp.logger.Error("Performing automatic rollback", "reason", reason)

	// 1. Quarantine current binary
	binaryPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	if _, err := sp.QuarantineFile(binaryPath, reason, 5); err != nil {
		sp.logger.Error("Failed to quarantine binary", "error", err)
	}

	// 2. Restore from backup
	backupBinary := filepath.Join(sp.backupDir, "binaries", "ai-governor.backup")
	if err := sp.restoreFromBackup(backupBinary, binaryPath); err != nil {
		return fmt.Errorf("failed to restore from backup: %w", err)
	}

	// 3. Send alert
	sp.sendForensicAlert(reason, map[string]interface{}{
		"action":      "auto_rollback",
		"binary_path": binaryPath,
		"backup_path": backupBinary,
		"timestamp":   time.Now(),
	})

	sp.logger.Info("Automatic rollback completed successfully")
	return nil
}

// restoreFromBackup restores a file from backup
func (sp *SandboxProtection) restoreFromBackup(backupPath, targetPath string) error {
	// Verify backup integrity before restore
	if err := sp.verifyBackupIntegrity(backupPath); err != nil {
		return fmt.Errorf("backup integrity check failed: %w", err)
	}

	// Copy backup to target location
	if err := copyFile(backupPath, targetPath); err != nil {
		return fmt.Errorf("failed to copy backup: %w", err)
	}

	// Set proper permissions
	if err := os.Chmod(targetPath, 0755); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	return nil
}

// verifyBackupIntegrity verifies the integrity of a backup file
func (sp *SandboxProtection) verifyBackupIntegrity(backupPath string) error {
	// This would verify the backup against stored checksums
	// For demonstration, we'll just check if the file exists and is readable
	if _, err := os.Stat(backupPath); err != nil {
		return fmt.Errorf("backup file not accessible: %w", err)
	}

	return nil
}

// sendForensicAlert sends a forensic alert to SIEM
func (sp *SandboxProtection) sendForensicAlert(reason string, metadata map[string]interface{}) {
	alert := map[string]interface{}{
		"timestamp":    time.Now(),
		"severity":     "critical",
		"category":     "security_incident",
		"reason":       reason,
		"metadata":     metadata,
		"source":       "ai-governor-sandbox",
		"hostname":     getHostname(),
		"process_id":   os.Getpid(),
	}

	// In production, this would send to actual SIEM
	sp.logger.Error("FORENSIC ALERT", "alert", alert)
}

// Helper functions

func getFileSize(filePath string) int64 {
	if info, err := os.Stat(filePath); err == nil {
		return info.Size()
	}
	return 0
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = destFile.ReadFrom(sourceFile)
	return err
}

func getHostname() string {
	if hostname, err := os.Hostname(); err == nil {
		return hostname
	}
	return "unknown"
}

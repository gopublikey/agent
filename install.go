package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

type InstallConfig struct {
	Token        string
	Endpoint     string
	UserMode     bool
	IncludeUsers []string
	ExcludeUsers []string
	Force        bool
	DryRun       bool
}

type Installer struct {
	config *InstallConfig
	logger *log.Logger
}

func NewInstaller(config *InstallConfig, logger *log.Logger) *Installer {
	return &Installer{
		config: config,
		logger: logger,
	}
}

func (i *Installer) Install() error {
	if i.config.DryRun {
		i.logger.Println("[DRY-RUN] Installation running in dry-run mode")
	}

	// Check platform compatibility
	if err := i.checkPlatformSupport(); err != nil {
		return err
	}

	// Validate configuration
	if err := i.validateConfig(); err != nil {
		return fmt.Errorf("configuration validation failed: %v", err)
	}

	// Check if systemd is available
	if !i.isSystemdAvailable() {
		return fmt.Errorf("systemd is not available - this installer requires a Linux system with systemd")
	}

	// Check permissions
	if err := i.checkPermissions(); err != nil {
		return fmt.Errorf("permission check failed: %v", err)
	}

	// Install binary
	if err := i.installBinary(); err != nil {
		return fmt.Errorf("binary installation failed: %v", err)
	}

	// Create service file
	if err := i.createServiceFile(); err != nil {
		return fmt.Errorf("service file creation failed: %v", err)
	}

	// Enable and start service
	if err := i.enableAndStartService(); err != nil {
		return fmt.Errorf("service activation failed: %v", err)
	}

	i.printInstallationSummary()
	return nil
}

func (i *Installer) validateConfig() error {
	if i.config.Token == "" {
		return fmt.Errorf("token is required")
	}
	if i.config.Endpoint == "" {
		return fmt.Errorf("endpoint is required")
	}
	if !strings.HasPrefix(i.config.Token, "pk_") {
		return fmt.Errorf("invalid token format (must start with 'pk_')")
	}
	if len(i.config.IncludeUsers) > 0 && len(i.config.ExcludeUsers) > 0 {
		return fmt.Errorf("cannot specify both include-users and exclude-users")
	}
	return nil
}

func (i *Installer) checkPlatformSupport() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("unsupported platform: %s. This installer only supports Linux systems with systemd.\n\nFor other platforms, you can:\n1. Build and run the agent manually\n2. Use the provided systemd service files as templates\n3. Create your own service management scripts", runtime.GOOS)
	}
	return nil
}

func (i *Installer) isSystemdAvailable() bool {
	_, err := exec.LookPath("systemctl")
	return err == nil
}

func (i *Installer) checkPermissions() error {
	if i.config.UserMode {
		// User mode: check if we can write to user directories
		currentUser, err := user.Current()
		if err != nil {
			return fmt.Errorf("failed to get current user: %v", err)
		}

		userBinDir := filepath.Join(currentUser.HomeDir, ".local", "bin")
		if err := os.MkdirAll(userBinDir, 0755); err != nil {
			return fmt.Errorf("cannot create user bin directory %s: %v", userBinDir, err)
		}

		systemdUserDir := filepath.Join(currentUser.HomeDir, ".config", "systemd", "user")
		if err := os.MkdirAll(systemdUserDir, 0755); err != nil {
			return fmt.Errorf("cannot create systemd user directory %s: %v", systemdUserDir, err)
		}
	} else {
		// System mode: check if running as root
		if os.Geteuid() != 0 {
			return fmt.Errorf("system mode installation requires root privileges.\n\nOptions:\n  1. Run with sudo: sudo ./pkagent install --token=%s --endpoint=%s\n  2. Install in user mode: ./pkagent install --token=%s --endpoint=%s --user-mode", i.config.Token, i.config.Endpoint, i.config.Token, i.config.Endpoint)
		}
	}
	return nil
}

func (i *Installer) installBinary() error {
	var destPath string

	if i.config.UserMode {
		currentUser, _ := user.Current()
		destPath = filepath.Join(currentUser.HomeDir, ".local", "bin", "pkagent")
	} else {
		destPath = "/usr/local/bin/pkagent"
	}

	// Get current executable path
	srcPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable path: %v", err)
	}

	if i.config.DryRun {
		i.logger.Printf("[DRY-RUN] Would copy %s to %s", srcPath, destPath)
		return nil
	}

	// Check if destination already exists
	if _, err := os.Stat(destPath); err == nil && !i.config.Force {
		return fmt.Errorf("binary already exists at %s (use --force to overwrite)", destPath)
	}

	// Copy the binary
	if err := i.copyFile(srcPath, destPath); err != nil {
		return fmt.Errorf("failed to copy binary: %v", err)
	}

	// Make it executable
	if err := os.Chmod(destPath, 0755); err != nil {
		return fmt.Errorf("failed to make binary executable: %v", err)
	}

	i.logger.Printf("Binary installed to %s", destPath)
	return nil
}

func (i *Installer) copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = dstFile.ReadFrom(srcFile)
	return err
}

func (i *Installer) createServiceFile() error {
	var servicePath string
	var serviceContent string

	if i.config.UserMode {
		currentUser, _ := user.Current()
		servicePath = filepath.Join(currentUser.HomeDir, ".config", "systemd", "user", "pkagent.service")
		serviceContent = i.generateUserServiceFile()
	} else {
		servicePath = "/etc/systemd/system/pkagent.service"
		serviceContent = i.generateSystemServiceFile()
	}

	if i.config.DryRun {
		i.logger.Printf("[DRY-RUN] Would create service file at %s", servicePath)
		i.logger.Printf("[DRY-RUN] Service file content:\n%s", serviceContent)
		return nil
	}

	// Check if service file already exists
	if _, err := os.Stat(servicePath); err == nil && !i.config.Force {
		return fmt.Errorf("service file already exists at %s (use --force to overwrite)", servicePath)
	}

	// Create the service file
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %v", err)
	}

	i.logger.Printf("Service file created at %s", servicePath)
	return nil
}

func (i *Installer) generateSystemServiceFile() string {
	userFilterArg := i.getUserFilterArg()

	return fmt.Sprintf(`[Unit]
Description=PubliKey Agent
Documentation=https://github.com/gopublikey/agent
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=simple
Restart=always
RestartSec=5
User=root
Group=root

# Environment variables
Environment=PUBLIKEY_TOKEN=%s
Environment=PUBLIKEY_ENDPOINT=%s

# Command
ExecStart=/usr/local/bin/pkagent --token=${PUBLIKEY_TOKEN} --endpoint=${PUBLIKEY_ENDPOINT}%s

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=false
ReadWritePaths=/home /root

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pkagent

# Process management
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
`, i.config.Token, i.config.Endpoint, userFilterArg)
}

func (i *Installer) generateUserServiceFile() string {
	currentUser, _ := user.Current()
	binaryPath := filepath.Join(currentUser.HomeDir, ".local", "bin", "pkagent")
	userFilterArg := i.getUserFilterArg()

	return fmt.Sprintf(`[Unit]
Description=PubliKey Agent (User Mode)
Documentation=https://github.com/gopublikey/agent
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=simple
Restart=always
RestartSec=5

# Environment variables
Environment=PUBLIKEY_TOKEN=%s
Environment=PUBLIKEY_ENDPOINT=%s

# Command
ExecStart=%s --token=${PUBLIKEY_TOKEN} --endpoint=${PUBLIKEY_ENDPOINT} --user-mode%s

# Security settings
NoNewPrivileges=true
PrivateTmp=true

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pkagent-user

# Process management
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30

[Install]
WantedBy=default.target
`, i.config.Token, i.config.Endpoint, binaryPath, userFilterArg)
}

func (i *Installer) getUserFilterArg() string {
	if len(i.config.IncludeUsers) > 0 {
		return " --include-users=" + strings.Join(i.config.IncludeUsers, ",")
	}
	if len(i.config.ExcludeUsers) > 0 {
		return " --exclude-users=" + strings.Join(i.config.ExcludeUsers, ",")
	}
	return ""
}

func (i *Installer) enableAndStartService() error {
	var systemctlCmd []string

	if i.config.UserMode {
		systemctlCmd = []string{"systemctl", "--user"}
	} else {
		systemctlCmd = []string{"systemctl"}
	}

	if i.config.DryRun {
		i.logger.Printf("[DRY-RUN] Would run: %s daemon-reload", strings.Join(systemctlCmd, " "))
		i.logger.Printf("[DRY-RUN] Would run: %s enable pkagent.service", strings.Join(systemctlCmd, " "))
		i.logger.Printf("[DRY-RUN] Would run: %s start pkagent.service", strings.Join(systemctlCmd, " "))
		return nil
	}

	// Reload systemd daemon
	cmd := exec.Command(systemctlCmd[0], append(systemctlCmd[1:], "daemon-reload")...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to reload systemd daemon: %v", err)
	}

	// Enable service
	cmd = exec.Command(systemctlCmd[0], append(systemctlCmd[1:], "enable", "pkagent.service")...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to enable service: %v", err)
	}

	// Start service
	cmd = exec.Command(systemctlCmd[0], append(systemctlCmd[1:], "start", "pkagent.service")...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to start service: %v", err)
	}

	i.logger.Println("Service enabled and started successfully")
	return nil
}

func (i *Installer) printInstallationSummary() {
	mode := "system"
	if i.config.UserMode {
		mode = "user"
	}

	fmt.Printf("\n=== PubliKey Agent Installation Complete ===\n")
	fmt.Printf("Mode: %s\n", mode)
	fmt.Printf("Token: %s...\n", i.config.Token[:10])
	fmt.Printf("Endpoint: %s\n", i.config.Endpoint)

	if len(i.config.IncludeUsers) > 0 {
		fmt.Printf("Included Users: %s\n", strings.Join(i.config.IncludeUsers, ", "))
	}
	if len(i.config.ExcludeUsers) > 0 {
		fmt.Printf("Excluded Users: %s\n", strings.Join(i.config.ExcludeUsers, ", "))
	}

	fmt.Println("\nService Management Commands:")
	if i.config.UserMode {
		fmt.Println("  Status:  systemctl --user status pkagent")
		fmt.Println("  Logs:    journalctl --user -u pkagent -f")
		fmt.Println("  Stop:    systemctl --user stop pkagent")
		fmt.Println("  Start:   systemctl --user start pkagent")
		fmt.Println("  Restart: systemctl --user restart pkagent")
	} else {
		fmt.Println("  Status:  systemctl status pkagent")
		fmt.Println("  Logs:    journalctl -u pkagent -f")
		fmt.Println("  Stop:    systemctl stop pkagent")
		fmt.Println("  Start:   systemctl start pkagent")
		fmt.Println("  Restart: systemctl restart pkagent")
	}

	fmt.Println("\nThe agent will:")
	fmt.Println("  - Report system information every 5 minutes")
	fmt.Println("  - Check for key assignments every 1 minute")
	fmt.Println("  - Automatically restart if it crashes")
	fmt.Println("  - Start automatically on boot")
}

func (i *Installer) Uninstall() error {
	if i.config.DryRun {
		i.logger.Println("[DRY-RUN] Uninstallation running in dry-run mode")
	}

	// Stop and disable service
	if err := i.stopAndDisableService(); err != nil {
		i.logger.Printf("Warning: failed to stop/disable service: %v", err)
	}

	// Remove service file
	if err := i.removeServiceFile(); err != nil {
		i.logger.Printf("Warning: failed to remove service file: %v", err)
	}

	// Remove binary
	if err := i.removeBinary(); err != nil {
		i.logger.Printf("Warning: failed to remove binary: %v", err)
	}

	i.logger.Println("Uninstallation completed")
	return nil
}

func (i *Installer) stopAndDisableService() error {
	var systemctlCmd []string

	if i.config.UserMode {
		systemctlCmd = []string{"systemctl", "--user"}
	} else {
		systemctlCmd = []string{"systemctl"}
	}

	if i.config.DryRun {
		i.logger.Printf("[DRY-RUN] Would run: %s stop pkagent.service", strings.Join(systemctlCmd, " "))
		i.logger.Printf("[DRY-RUN] Would run: %s disable pkagent.service", strings.Join(systemctlCmd, " "))
		return nil
	}

	// Stop service (ignore errors if service doesn't exist)
	cmd := exec.Command(systemctlCmd[0], append(systemctlCmd[1:], "stop", "pkagent.service")...)
	cmd.Run()

	// Disable service (ignore errors if service doesn't exist)
	cmd = exec.Command(systemctlCmd[0], append(systemctlCmd[1:], "disable", "pkagent.service")...)
	cmd.Run()

	// Reload daemon
	cmd = exec.Command(systemctlCmd[0], append(systemctlCmd[1:], "daemon-reload")...)
	return cmd.Run()
}

func (i *Installer) removeServiceFile() error {
	var servicePath string

	if i.config.UserMode {
		currentUser, _ := user.Current()
		servicePath = filepath.Join(currentUser.HomeDir, ".config", "systemd", "user", "pkagent.service")
	} else {
		servicePath = "/etc/systemd/system/pkagent.service"
	}

	if i.config.DryRun {
		i.logger.Printf("[DRY-RUN] Would remove service file: %s", servicePath)
		return nil
	}

	if _, err := os.Stat(servicePath); err == nil {
		if err := os.Remove(servicePath); err != nil {
			return fmt.Errorf("failed to remove service file %s: %v", servicePath, err)
		}
		i.logger.Printf("Removed service file: %s", servicePath)
	}

	return nil
}

func (i *Installer) removeBinary() error {
	var binaryPath string

	if i.config.UserMode {
		currentUser, _ := user.Current()
		binaryPath = filepath.Join(currentUser.HomeDir, ".local", "bin", "pkagent")
	} else {
		binaryPath = "/usr/local/bin/pkagent"
	}

	if i.config.DryRun {
		i.logger.Printf("[DRY-RUN] Would remove binary: %s", binaryPath)
		return nil
	}

	if _, err := os.Stat(binaryPath); err == nil {
		if err := os.Remove(binaryPath); err != nil {
			return fmt.Errorf("failed to remove binary %s: %v", binaryPath, err)
		}
		i.logger.Printf("Removed binary: %s", binaryPath)
	}

	return nil
}

// Service status check
func (i *Installer) Status() error {
	var systemctlCmd []string

	if i.config.UserMode {
		systemctlCmd = []string{"systemctl", "--user", "status", "pkagent.service"}
	} else {
		systemctlCmd = []string{"systemctl", "status", "pkagent.service"}
	}

	cmd := exec.Command(systemctlCmd[0], systemctlCmd[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

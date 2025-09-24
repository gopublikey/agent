package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	Version   = "0.9.2"
	UserAgent = "PubliKey-Agent/" + Version
)

type Config struct {
	Token            string
	Endpoint         string
	UserMode         bool
	DryRun           bool
	ReportInterval   time.Duration
	KeyCheckInterval time.Duration
	IncludeUsers     []string
	ExcludeUsers     []string
	LogLevel         string
}

type SystemInfo struct {
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	Platform     string `json:"platform"`
	Kernel       string `json:"kernel"`
	Distribution string `json:"distribution"`
	Version      string `json:"version"`
	SSHPort      int    `json:"sshPort"`
}

type UserInfo struct {
	Username string `json:"username"`
	UID      int    `json:"uid"`
	Shell    string `json:"shell"`
	HomeDir  string `json:"home_dir"`
	Disabled bool   `json:"disabled"`
}

type ReportRequest struct {
	Hostname     string     `json:"hostname"`
	SystemInfo   SystemInfo `json:"systemInfo"`
	AgentVersion string     `json:"agentVersion"`
	Users        []UserInfo `json:"users"`
}

type KeyAssignment struct {
	Username      string `json:"username"`
	Fingerprint   string `json:"fingerprint"`
	PublicKey     string `json:"publicKey"`
	KeyType       string `json:"keyType"`
	Comment       string `json:"comment"`
	UsePrimaryKey bool   `json:"usePrimaryKey"`
	AssignmentID  string `json:"assignmentId"`
	KeySource     string `json:"keySource"`
	Purpose       string `json:"purpose,omitempty"`
}

type KeyAssignmentsResponse struct {
	Success     bool            `json:"success"`
	HostID      string          `json:"hostId"`
	Hostname    string          `json:"hostname"`
	Assignments []KeyAssignment `json:"assignments"`
	Timestamp   string          `json:"timestamp"`
}

type GitHubRelease struct {
	TagName string `json:"tag_name"`
	Name    string `json:"name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

type UpdateConfig struct {
	DryRun bool
	Force  bool
}

type Agent struct {
	config     *Config
	logger     *log.Logger
	httpClient *http.Client
	hostname   string
	systemInfo SystemInfo
	sshPaths   map[string][]string // username -> authorized_keys paths
}

func main() {
	// Check if this is a subcommand
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			handleInstallCommand()
			return
		case "uninstall":
			handleUninstallCommand()
			return
		case "status":
			handleStatusCommand()
			return
		case "update":
			handleUpdateCommand()
			return
		}
	}

	// Default behavior: run the agent
	config := parseFlags()

	agent, err := NewAgent(config)
	if err != nil {
		log.Fatalf("Failed to create agent: %v", err)
	}

	if config.DryRun {
		agent.logger.Println("[DRY-RUN] Agent running in dry-run mode - no changes will be made")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		agent.logger.Println("Received shutdown signal, stopping agent...")
		cancel()
	}()

	agent.logger.Printf("PubliKey Agent %s starting...", Version)
	agent.logger.Printf("Mode: %s", func() string {
		if config.UserMode {
			return "user"
		}
		return "system"
	}())

	if err := agent.Run(ctx); err != nil {
		log.Fatalf("Agent failed: %v", err)
	}
}

func parseFlags() *Config {
	config := &Config{}

	flag.StringVar(&config.Token, "token", "", "Agent authentication token")
	flag.StringVar(&config.Endpoint, "endpoint", "", "API endpoint URL")
	flag.BoolVar(&config.UserMode, "user-mode", false, "Run in user mode (manage only current user)")
	flag.BoolVar(&config.DryRun, "dry-run", false, "Dry run mode (no actual changes)")
	flag.DurationVar(&config.ReportInterval, "report-interval", 5*time.Minute, "System report interval")
	flag.DurationVar(&config.KeyCheckInterval, "key-check-interval", 1*time.Minute, "Key check interval")

	var includeUsers, excludeUsers string
	flag.StringVar(&includeUsers, "include-users", "", "Comma-separated list of users to include")
	flag.StringVar(&excludeUsers, "exclude-users", "", "Comma-separated list of users to exclude")
	flag.StringVar(&config.LogLevel, "log-level", "info", "Log level (debug, info, warn, error)")

	version := flag.Bool("version", false, "Show version and exit")

	flag.Parse()

	if *version {
		fmt.Printf("PubliKey Agent %s\n", Version)
		os.Exit(0)
	}

	// Parse user filters
	if includeUsers != "" {
		config.IncludeUsers = strings.Split(includeUsers, ",")
	}
	if excludeUsers != "" {
		config.ExcludeUsers = strings.Split(excludeUsers, ",")
	}

	// Get from environment if not provided via flags
	if config.Token == "" {
		config.Token = os.Getenv("PUBLIKEY_TOKEN")
	}
	if config.Endpoint == "" {
		config.Endpoint = os.Getenv("PUBLIKEY_ENDPOINT")
	}

	if config.Token == "" || config.Endpoint == "" {
		log.Fatal("Token and endpoint are required (use flags or environment variables)")
	}

	return config
}

func NewAgent(config *Config) (*Agent, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname: %v", err)
	}

	logger := log.New(os.Stdout, "", log.LstdFlags)

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	agent := &Agent{
		config:     config,
		logger:     logger,
		httpClient: httpClient,
		hostname:   hostname,
		sshPaths:   make(map[string][]string),
	}

	// Initialize system info
	if err := agent.collectSystemInfo(); err != nil {
		return nil, fmt.Errorf("failed to collect system info: %v", err)
	}

	return agent, nil
}

func (a *Agent) Run(ctx context.Context) error {
	// Initial system report
	if err := a.reportToServer(); err != nil {
		a.logger.Printf("Initial system report failed: %v", err)
	}

	reportTicker := time.NewTicker(a.config.ReportInterval)
	defer reportTicker.Stop()

	keyTicker := time.NewTicker(a.config.KeyCheckInterval)
	defer keyTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.logger.Println("Agent stopped")
			return nil

		case <-reportTicker.C:
			if err := a.reportToServer(); err != nil {
				a.logger.Printf("System report failed: %v", err)
			}

		case <-keyTicker.C:
			if err := a.processKeyAssignments(); err != nil {
				a.logger.Printf("Key processing failed: %v", err)
			}
		}
	}
}

func (a *Agent) collectSystemInfo() error {
	a.systemInfo = SystemInfo{
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Platform: runtime.GOOS,
	}

	// Get kernel version
	if output, err := exec.Command("uname", "-r").Output(); err == nil {
		a.systemInfo.Kernel = strings.TrimSpace(string(output))
	}

	// Get distribution info on Linux
	if runtime.GOOS == "linux" {
		if err := a.parseOSRelease(); err != nil {
			a.logger.Printf("Warning: Could not parse OS release info: %v", err)
		}
	} else if runtime.GOOS == "darwin" {
		a.systemInfo.Distribution = "macOS"
		if output, err := exec.Command("sw_vers", "-productVersion").Output(); err == nil {
			a.systemInfo.Version = strings.TrimSpace(string(output))
		}
	}

	// Get SSH port
	a.systemInfo.SSHPort = a.getSSHPort()

	return nil
}

func (a *Agent) parseOSRelease() error {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "ID=") {
			a.systemInfo.Distribution = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
		} else if strings.HasPrefix(line, "VERSION_ID=") {
			a.systemInfo.Version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
		}
	}

	return scanner.Err()
}

func (a *Agent) getSSHPort() int {
	port := 22 // default

	file, err := os.Open("/etc/ssh/sshd_config")
	if err != nil {
		return port
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Port ") {
			if p, err := strconv.Atoi(strings.Fields(line)[1]); err == nil {
				port = p
				break
			}
		}
	}

	return port
}

func (a *Agent) getSystemUsers() ([]UserInfo, error) {
	var users []UserInfo

	if a.config.UserMode {
		// User mode: only current user
		currentUser, err := user.Current()
		if err != nil {
			return nil, fmt.Errorf("failed to get current user: %v", err)
		}

		uid, err := strconv.Atoi(currentUser.Uid)
		if err != nil {
			return nil, fmt.Errorf("failed to parse UID: %v", err)
		}

		users = append(users, UserInfo{
			Username: currentUser.Username,
			UID:      uid,
			Shell:    getShellFromPasswd(currentUser.Username),
			HomeDir:  currentUser.HomeDir,
			Disabled: false,
		})
	} else {
		// System mode: all users with UID > 999
		file, err := os.Open("/etc/passwd")
		if err != nil {
			return nil, fmt.Errorf("failed to read /etc/passwd: %v", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Split(line, ":")
			if len(fields) < 7 {
				continue
			}

			username := fields[0]
			uid, err := strconv.Atoi(fields[2])
			if err != nil {
				continue
			}

			// Skip system users
			// Include: root (UID 0) and regular users (UID 1000-60000)
			// Exclude: system users (UID 1-999) and reserved UIDs (> 60000 like nobody:65534)
			if uid != 0 && (uid < 1000 || uid > 60000) {
				continue
			}

			// Apply user filters
			if !a.shouldIncludeUser(username) {
				continue
			}

			users = append(users, UserInfo{
				Username: username,
				UID:      uid,
				Shell:    fields[6],
				HomeDir:  fields[5],
				Disabled: false, // Would need additional logic to detect
			})
		}
	}

	// Analyze SSH configuration for each user
	for i := range users {
		a.analyzeUserSSHConfig(&users[i])
	}

	return users, nil
}

func getShellFromPasswd(username string) string {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return "/bin/bash" // default
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) >= 7 && fields[0] == username {
			return fields[6]
		}
	}

	return "/bin/bash"
}

func (a *Agent) shouldIncludeUser(username string) bool {
	// Check exclude list first
	for _, excludeUser := range a.config.ExcludeUsers {
		if username == excludeUser {
			return false
		}
	}

	// If include list is specified, user must be in it
	if len(a.config.IncludeUsers) > 0 {
		for _, includeUser := range a.config.IncludeUsers {
			if username == includeUser {
				return true
			}
		}
		return false
	}

	return true
}

func (a *Agent) analyzeUserSSHConfig(userInfo *UserInfo) {
	var authorizedKeysPaths []string

	// Default location
	defaultPath := filepath.Join(userInfo.HomeDir, ".ssh", "authorized_keys")
	authorizedKeysPaths = append(authorizedKeysPaths, defaultPath)

	// Parse sshd_config for additional AuthorizedKeysFile directives
	if additionalPaths := a.parseAuthorizedKeysFile(userInfo); len(additionalPaths) > 0 {
		authorizedKeysPaths = append(authorizedKeysPaths, additionalPaths...)
	}

	a.sshPaths[userInfo.Username] = authorizedKeysPaths
}

func (a *Agent) parseAuthorizedKeysFile(userInfo *UserInfo) []string {
	var paths []string

	file, err := os.Open("/etc/ssh/sshd_config")
	if err != nil {
		return paths
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "AuthorizedKeysFile ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				for _, field := range fields[1:] {
					// Replace tokens
					path := strings.ReplaceAll(field, "%h", userInfo.HomeDir)
					path = strings.ReplaceAll(path, "%u", userInfo.Username)

					// Make absolute path
					if !filepath.IsAbs(path) {
						path = filepath.Join(userInfo.HomeDir, path)
					}

					paths = append(paths, path)
				}
			}
		}
	}

	return paths
}

func (a *Agent) reportToServer() error {
	users, err := a.getSystemUsers()
	if err != nil {
		return fmt.Errorf("failed to get system users: %v", err)
	}

	request := ReportRequest{
		Hostname:     a.hostname,
		SystemInfo:   a.systemInfo,
		AgentVersion: Version,
		Users:        users,
	}

	return a.makeAPIRequest("POST", "/api/agent/report", request, nil)
}

func (a *Agent) processKeyAssignments() error {
	var response KeyAssignmentsResponse
	if err := a.makeAPIRequest("GET", "/api/host/keys", nil, &response); err != nil {
		return err
	}

	// Group assignments by username
	userAssignments := make(map[string][]KeyAssignment)
	for _, assignment := range response.Assignments {
		userAssignments[assignment.Username] = append(userAssignments[assignment.Username], assignment)
	}

	// Process each user's assignments
	for username, assignments := range userAssignments {
		if err := a.deployKeysForUser(username, assignments); err != nil {
			a.logger.Printf("Failed to deploy keys for user %s: %v", username, err)
		}
	}

	return nil
}

func (a *Agent) deployKeysForUser(username string, assignments []KeyAssignment) error {
	// Get user info
	userInfo, err := user.Lookup(username)
	if err != nil {
		a.logger.Printf("User %s not found, skipping", username)
		return nil
	}

	// Check if we should manage this user
	if !a.shouldIncludeUser(username) {
		return nil
	}

	// Get authorized_keys paths for this user
	paths, exists := a.sshPaths[username]
	if !exists {
		// Fallback to default path
		paths = []string{filepath.Join(userInfo.HomeDir, ".ssh", "authorized_keys")}
	}

	for _, path := range paths {
		if err := a.updateAuthorizedKeysFile(path, userInfo, assignments); err != nil {
			a.logger.Printf("Failed to update %s: %v", path, err)
		}
	}

	return nil
}

func (a *Agent) updateAuthorizedKeysFile(filePath string, userInfo *user.User, assignments []KeyAssignment) error {
	sshDir := filepath.Dir(filePath)

	// Create .ssh directory if it doesn't exist
	if !a.config.DryRun {
		if err := os.MkdirAll(sshDir, 0700); err != nil {
			return fmt.Errorf("failed to create SSH directory: %v", err)
		}

		// Set ownership
		uid, _ := strconv.Atoi(userInfo.Uid)
		gid, _ := strconv.Atoi(userInfo.Gid)
		if err := os.Chown(sshDir, uid, gid); err != nil {
			a.logger.Printf("Warning: Could not set ownership of %s: %v", sshDir, err)
		}
	} else {
		a.logger.Printf("[DRY-RUN] Would create directory: %s", sshDir)
	}

	// Note: We no longer read existing keys as PubliKey has exclusive control

	// PubliKey exclusive mode - only deploy PubliKey-managed keys
	// All existing keys are removed and replaced with only the assigned keys
	var newKeys []string

	// Add PubliKey header comment
	newKeys = append(newKeys, "# PubliKey managed - do not edit manually")
	newKeys = append(newKeys, "# This file is managed by PubliKey Agent")
	newKeys = append(newKeys, "# Manual changes will be overwritten")

	// Add new PubliKey-managed keys
	for _, assignment := range assignments {
		if !a.isValidSSHKey(assignment.PublicKey) {
			a.logger.Printf("Invalid SSH key for assignment %s, skipping", assignment.AssignmentID)
			continue
		}

		keyLine := fmt.Sprintf("%s # PubliKey:%s:%s",
			assignment.PublicKey, assignment.AssignmentID, assignment.KeySource)
		newKeys = append(newKeys, keyLine)
	}

	// Only use PubliKey-managed keys (no preserved keys)
	allKeys := newKeys
	content := strings.Join(allKeys, "\n")
	if len(allKeys) > 0 {
		content += "\n"
	}

	if a.config.DryRun {
		a.logger.Printf("[DRY-RUN] Would write %d keys to %s", len(newKeys), filePath)
		return nil
	}

	// Write the file
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write authorized_keys: %v", err)
	}

	// Set ownership
	uid, _ := strconv.Atoi(userInfo.Uid)
	gid, _ := strconv.Atoi(userInfo.Gid)
	if err := os.Chown(filePath, uid, gid); err != nil {
		a.logger.Printf("Warning: Could not set ownership of %s: %v", filePath, err)
	}

	a.logger.Printf("Deployed %d keys for user %s", len(newKeys), userInfo.Username)
	return nil
}

func (a *Agent) isValidSSHKey(key string) bool {
	// Basic validation of SSH key format
	parts := strings.Fields(key)
	if len(parts) < 2 {
		return false
	}

	keyType := parts[0]
	validTypes := []string{
		"ssh-rsa", "ssh-dss", "ssh-ed25519",
		"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
	}

	for _, valid := range validTypes {
		if keyType == valid {
			return true
		}
	}

	return false
}

func (a *Agent) makeAPIRequest(method, endpoint string, requestBody, responseBody interface{}) error {
	url := strings.TrimSuffix(a.config.Endpoint, "/") + endpoint

	var body io.Reader
	if requestBody != nil {
		jsonData, err := json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %v", err)
		}
		body = bytes.NewBuffer(jsonData)
	}

	// Retry logic with exponential backoff
	maxRetries := 5
	for attempt := 0; attempt < maxRetries; attempt++ {
		req, err := http.NewRequest(method, url, body)
		if err != nil {
			return fmt.Errorf("failed to create request: %v", err)
		}

		req.Header.Set("Authorization", "Bearer "+a.config.Token)
		req.Header.Set("User-Agent", UserAgent)
		if requestBody != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := a.httpClient.Do(req)
		if err != nil {
			if attempt < maxRetries-1 {
				delay := time.Duration(1<<attempt)*time.Second + time.Duration(rand.Intn(1000))*time.Millisecond
				a.logger.Printf("Request failed (attempt %d/%d), retrying in %v: %v", attempt+1, maxRetries, delay, err)
				time.Sleep(delay)
				continue
			}
			return fmt.Errorf("request failed after %d attempts: %v", maxRetries, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			if responseBody != nil {
				return json.NewDecoder(resp.Body).Decode(responseBody)
			}
			return nil
		}

		// Don't retry authentication or deactivation errors
		if resp.StatusCode == 401 || resp.StatusCode == 405 {
			return fmt.Errorf("authentication failed or host deactivated: %d", resp.StatusCode)
		}

		// Retry server errors
		if resp.StatusCode >= 500 && attempt < maxRetries-1 {
			delay := time.Duration(1<<attempt)*time.Second + time.Duration(rand.Intn(1000))*time.Millisecond
			a.logger.Printf("Server error %d (attempt %d/%d), retrying in %v", resp.StatusCode, attempt+1, maxRetries, delay)
			time.Sleep(delay)
			continue
		}

		return fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	return errors.New("max retries exceeded")
}

// Update functions
func getLatestRelease() (*GitHubRelease, error) {
	url := "https://api.github.com/repos/gopublikey/agent/releases/latest"

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch latest release: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to parse release data: %v", err)
	}

	return &release, nil
}

func compareVersions(current, latest string) (bool, error) {
	// Remove 'v' prefix if present
	current = strings.TrimPrefix(current, "v")
	latest = strings.TrimPrefix(latest, "v")

	// Simple string comparison for semantic versions
	// In production, consider using a proper semver library
	return current != latest, nil
}

func getAssetForCurrentPlatform(release *GitHubRelease) (string, string, error) {
	// Determine the expected binary name for current platform
	var expectedName string
	switch runtime.GOOS {
	case "linux":
		switch runtime.GOARCH {
		case "amd64":
			expectedName = "pkagent-linux-x86_64"
		case "arm64":
			expectedName = "pkagent-linux-aarch64"
		case "arm":
			expectedName = "pkagent-linux-arm"
		case "386":
			expectedName = "pkagent-linux-i386"
		default:
			return "", "", fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
		}
	default:
		return "", "", fmt.Errorf("PubliKey Agent only supports Linux. Current platform: %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	// Find the matching asset
	for _, asset := range release.Assets {
		if asset.Name == expectedName {
			return asset.Name, asset.BrowserDownloadURL, nil
		}
	}

	return "", "", fmt.Errorf("no binary found for platform %s/%s", runtime.GOOS, runtime.GOARCH)
}

func downloadBinary(url, targetPath string) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download binary: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	file, err := os.Create(targetPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}

	// Make executable
	if err := os.Chmod(targetPath, 0755); err != nil {
		return fmt.Errorf("failed to set executable permissions: %v", err)
	}

	return nil
}

func getCurrentBinaryPath() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %v", err)
	}
	return filepath.EvalSymlinks(executable)
}

func updateBinary(downloadURL, tempPath string, dryRun bool) error {
	currentPath, err := getCurrentBinaryPath()
	if err != nil {
		return err
	}

	if dryRun {
		log.Printf("[DRY-RUN] Would download %s to %s", downloadURL, tempPath)
		log.Printf("[DRY-RUN] Would replace %s with new binary", currentPath)
		return nil
	}

	// Download to temporary file
	log.Printf("Downloading update from %s...", downloadURL)
	if err := downloadBinary(downloadURL, tempPath); err != nil {
		return err
	}

	// Verify the downloaded binary
	log.Printf("Verifying downloaded binary...")
	cmd := exec.Command(tempPath, "--version")
	if err := cmd.Run(); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("downloaded binary failed verification: %v", err)
	}

	// Replace current binary
	log.Printf("Replacing current binary at %s...", currentPath)
	if err := os.Rename(tempPath, currentPath); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("failed to replace binary: %v", err)
	}

	return nil
}

func handleUpdateCommand() {
	updateCmd := flag.NewFlagSet("update", flag.ExitOnError)

	config := &UpdateConfig{}
	updateCmd.BoolVar(&config.DryRun, "dry-run", false, "Show what would be done without making changes")
	updateCmd.BoolVar(&config.Force, "force", false, "Force update even if versions are the same")

	updateCmd.Usage = func() {
		fmt.Fprintf(os.Stderr, "Update PubliKey Agent to the latest version\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s update [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		updateCmd.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Check for and install updates\n")
		fmt.Fprintf(os.Stderr, "  %s update\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Check what would be updated without installing\n")
		fmt.Fprintf(os.Stderr, "  %s update --dry-run\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Force update even if versions are the same\n")
		fmt.Fprintf(os.Stderr, "  %s update --force\n\n", os.Args[0])
	}

	updateCmd.Parse(os.Args[2:])

	log.Printf("PubliKey Agent Updater")
	log.Printf("Current version: %s", Version)

	// Get latest release from GitHub
	log.Printf("Checking for updates...")
	release, err := getLatestRelease()
	if err != nil {
		log.Fatalf("Failed to check for updates: %v", err)
	}

	log.Printf("Latest version: %s", release.TagName)

	// Compare versions
	needsUpdate, err := compareVersions(Version, release.TagName)
	if err != nil {
		log.Fatalf("Failed to compare versions: %v", err)
	}

	if !needsUpdate && !config.Force {
		log.Printf("Already running the latest version (%s)", Version)
		return
	}

	if config.Force {
		log.Printf("Force update requested")
	} else {
		log.Printf("Update available: %s -> %s", Version, release.TagName)
	}

	// Get download URL for current platform
	assetName, downloadURL, err := getAssetForCurrentPlatform(release)
	if err != nil {
		log.Fatalf("Failed to find binary for current platform: %v", err)
	}

	log.Printf("Found binary: %s", assetName)

	// Create temporary file for download
	tempDir := "/tmp"
	if config.DryRun {
		tempDir = "/tmp" // Keep simple for dry run
	}
	tempPath := filepath.Join(tempDir, "pkagent-update-"+strconv.FormatInt(time.Now().Unix(), 10))

	// Perform the update
	if err := updateBinary(downloadURL, tempPath, config.DryRun); err != nil {
		log.Fatalf("Update failed: %v", err)
	}

	if config.DryRun {
		log.Printf("[DRY-RUN] Update process completed successfully")
		log.Printf("[DRY-RUN] Would have updated from %s to %s", Version, release.TagName)
	} else {
		log.Printf("Update completed successfully!")
		log.Printf("Updated from %s to %s", Version, release.TagName)
		log.Printf("Please restart any running services to use the new version")
	}
}

// Install command handlers
func handleInstallCommand() {
	installCmd := flag.NewFlagSet("install", flag.ExitOnError)

	config := &InstallConfig{}
	installCmd.StringVar(&config.Token, "token", "", "Agent authentication token (required)")
	installCmd.StringVar(&config.Endpoint, "endpoint", "", "API endpoint URL (required)")
	installCmd.BoolVar(&config.UserMode, "user-mode", false, "Install as user service (default: system service)")
	installCmd.BoolVar(&config.Force, "force", false, "Overwrite existing installation")
	installCmd.BoolVar(&config.DryRun, "dry-run", false, "Show what would be done without making changes")

	var includeUsers, excludeUsers string
	installCmd.StringVar(&includeUsers, "include-users", "", "Comma-separated list of users to include")
	installCmd.StringVar(&excludeUsers, "exclude-users", "", "Comma-separated list of users to exclude")

	installCmd.Usage = func() {
		fmt.Fprintf(os.Stderr, "Install PubliKey Agent as a systemd service\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s install [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		installCmd.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Install as system service\n")
		fmt.Fprintf(os.Stderr, "  sudo %s install --token=pk_abc123 --endpoint=https://demo.publikey.io\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Install as user service\n")
		fmt.Fprintf(os.Stderr, "  %s install --token=pk_abc123 --endpoint=https://demo.publikey.io --user-mode\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Dry run to see what would be done\n")
		fmt.Fprintf(os.Stderr, "  %s install --token=pk_abc123 --endpoint=https://demo.publikey.io --dry-run\n\n", os.Args[0])
	}

	installCmd.Parse(os.Args[2:])

	// Get from environment if not provided via flags
	if config.Token == "" {
		config.Token = os.Getenv("PUBLIKEY_TOKEN")
	}
	if config.Endpoint == "" {
		config.Endpoint = os.Getenv("PUBLIKEY_ENDPOINT")
	}

	// Parse user filters
	if includeUsers != "" {
		config.IncludeUsers = strings.Split(includeUsers, ",")
	}
	if excludeUsers != "" {
		config.ExcludeUsers = strings.Split(excludeUsers, ",")
	}

	logger := log.New(os.Stdout, "", log.LstdFlags)
	installer := NewInstaller(config, logger)

	if err := installer.Install(); err != nil {
		log.Fatalf("Installation failed: %v", err)
	}
}

func handleUninstallCommand() {
	uninstallCmd := flag.NewFlagSet("uninstall", flag.ExitOnError)

	config := &InstallConfig{}
	uninstallCmd.BoolVar(&config.UserMode, "user-mode", false, "Uninstall user service (default: system service)")
	uninstallCmd.BoolVar(&config.DryRun, "dry-run", false, "Show what would be done without making changes")

	uninstallCmd.Usage = func() {
		fmt.Fprintf(os.Stderr, "Uninstall PubliKey Agent systemd service\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s uninstall [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		uninstallCmd.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Uninstall system service\n")
		fmt.Fprintf(os.Stderr, "  sudo %s uninstall\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Uninstall user service\n")
		fmt.Fprintf(os.Stderr, "  %s uninstall --user-mode\n\n", os.Args[0])
	}

	uninstallCmd.Parse(os.Args[2:])

	logger := log.New(os.Stdout, "", log.LstdFlags)
	installer := NewInstaller(config, logger)

	if err := installer.Uninstall(); err != nil {
		log.Fatalf("Uninstallation failed: %v", err)
	}
}

func handleStatusCommand() {
	statusCmd := flag.NewFlagSet("status", flag.ExitOnError)

	config := &InstallConfig{}
	statusCmd.BoolVar(&config.UserMode, "user-mode", false, "Check user service status (default: system service)")

	statusCmd.Usage = func() {
		fmt.Fprintf(os.Stderr, "Check PubliKey Agent service status\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s status [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		statusCmd.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Check system service status\n")
		fmt.Fprintf(os.Stderr, "  %s status\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Check user service status\n")
		fmt.Fprintf(os.Stderr, "  %s status --user-mode\n\n", os.Args[0])
	}

	statusCmd.Parse(os.Args[2:])

	logger := log.New(os.Stdout, "", log.LstdFlags)
	installer := NewInstaller(config, logger)

	if err := installer.Status(); err != nil {
		os.Exit(1) // systemctl returns non-zero for inactive services
	}
}

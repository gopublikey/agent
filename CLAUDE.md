# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go implementation of a PubliKey agent - a client that communicates with the PubliKey SSH Key Management Platform to manage SSH key deployments on remote hosts. The agent reports system information, retrieves key assignments, and deploys SSH keys to user accounts.

## Common Commands

### Build and Run
```bash
make build                           # Build the agent binary
make dev                            # Full development workflow (fmt, vet, test, build)
make release                        # Build for all platforms
go run main.go --help               # Show command line options
./pkagent --version                 # Show version
```

### Development and Testing
```bash
make fmt                            # Format Go code
make vet                            # Run Go static analyzer
make test                           # Run tests
make dry-run TOKEN=pk_abc ENDPOINT=https://api.example.com  # Test without changes
```

### Installation
```bash
# Production installation (server-provided script with baked-in config)
curl -sSL https://your-server.com/install.sh?token=pk_abc | sudo bash  # System service
curl -sSL https://your-server.com/install.sh?token=pk_abc | bash -s -- --user-mode  # User service

# Development/manual installation
./pkagent install --token=pk_abc --endpoint=https://api.example.com  # System service
./pkagent install --token=pk_abc --endpoint=https://api.example.com --user-mode  # User service
./pkagent install --help           # Show installation options

# Development builds (Makefile available when developing)
make install-service TOKEN=pk_abc ENDPOINT=https://api.example.com  # System service
make install-user-service TOKEN=pk_abc ENDPOINT=https://api.example.com  # User service
```

### Version Management
```bash
./version.sh get                    # Show current version
./version.sh bump patch             # Bump patch version (0.6.0 -> 0.6.1)
./version.sh bump minor             # Bump minor version (0.6.0 -> 0.7.0)
./version.sh set 1.0.0             # Set specific version
make version-bump-patch             # Alternative via Makefile
```

### Service Management
```bash
# Built-in service management
./pkagent status                    # Check system service status
./pkagent status --user-mode        # Check user service status
./pkagent uninstall                 # Uninstall system service
./pkagent uninstall --user-mode     # Uninstall user service

# Direct systemctl commands
systemctl status pkagent            # Check service status
systemctl start pkagent             # Start service
systemctl stop pkagent              # Stop service
journalctl -u pkagent -f            # View logs

# User service
systemctl --user status pkagent     # Check user service status
systemctl --user start pkagent      # Start user service
journalctl --user -u pkagent -f     # View user service logs
```

## Architecture

The project implements a PubliKey agent that communicates with a PubliKey server via REST API. Key responsibilities include:

1. **System Discovery** - Detect OS, architecture, distribution, and enumerate system users
2. **Periodic Reporting** - Send system information and user lists to `/api/agent/report`
3. **Key Management** - Retrieve key assignments from `/api/host/keys` and deploy to `~/.ssh/authorized_keys`
4. **Security** - Authenticate with agent tokens, validate SSH keys, maintain proper file permissions

### API Integration

The agent communicates with three main endpoints:
- `GET /api/health` - Health check (no auth required)
- `POST /api/agent/report` - Report system info and users (requires agent token)
- `GET /api/host/keys` - Retrieve SSH key assignments (requires agent token)

Authentication uses Bearer tokens with format `pk_*`.

### Key Features to Implement

Based on the API documentation in `.docs/API.md`, the agent should:
- Report system information including OS details, architecture, kernel version, SSH port
- Enumerate system users with UID, shell, home directory information
- Deploy SSH keys while preserving non-PubliKey managed keys
- Handle key additions, removals, and updates with proper atomic operations
- Implement exponential backoff for API request retries
- Maintain audit logs and handle authentication/network errors gracefully

## Implementation Features

The agent is fully implemented with the following capabilities:

### Core Functionality
- **Dual Mode Operation**: Runs in either system mode (manages all users with UID > 999) or user mode (manages only current user)
- **Continuous Service**: Runs as a systemd service instead of a timer-based approach
- **SSH Config Analysis**: Parses `sshd_config` to find all `AuthorizedKeysFile` locations and manages keys accordingly
- **Dry Run Mode**: `--dry-run` flag allows testing without making actual changes
- **User Filtering**: Support for `--include-users` and `--exclude-users` parameters

### System Integration
- **Signal Handling**: Graceful shutdown on SIGINT/SIGTERM
- **Retry Logic**: Exponential backoff for API requests with proper error handling
- **Logging**: Structured logging with appropriate log levels
- **Service Files**: Both system and user systemd service configurations included
- **Installation Script**: Automated installation with support for both modes

### Security Features
- **Key Validation**: Validates SSH key formats before deployment
- **File Permissions**: Maintains proper ownership and permissions (700 for .ssh, 600 for authorized_keys)
- **Privilege Separation**: Runs with minimal required privileges
- **Key Preservation**: Preserves non-PubliKey managed keys while updating managed ones

### Development Tools
- **Version Management**: `version.sh` script for semantic versioning
- **Build System**: Comprehensive Makefile with development and release targets
- **Multi-architecture Builds**: Support for all major Linux architectures (x86_64, ARM64, ARM, i386)

## Project Structure
```
├── main.go                 # Main agent implementation
├── install.go              # Built-in installer module with systemd integration
├── version.sh             # Version management script (development)
├── Makefile               # Build and development commands (development)
├── go.mod                 # Go module definition
├── .gitignore             # Git ignore patterns
├── CLAUDE.md              # Development guidance
├── README.md              # Project documentation
├── .github/
│   └── workflows/
│       └── build.yml      # GitHub Actions build and release workflow
└── .docs/
    └── API.md             # API documentation
```

**Note**: The installer dynamically generates systemd service files and the PubliKey server templates the installation script with user-specific tokens.

## Installation Module Features

The built-in installer (`install.go`) provides:

- **Platform Detection**: Linux-only with clear error messages for other platforms
- **Service Management**: Complete systemd service lifecycle (install, start, stop, uninstall)
- **Dual Mode Support**: System-wide or user-specific installations
- **Dry Run Mode**: Preview installations without making changes
- **Force Overwrite**: Replace existing installations
- **Binary Management**: Automatic binary copying and permission setting
- **Configuration Validation**: Ensures tokens and endpoints are valid
- **User Filtering**: Support for include/exclude user lists in service configuration

## Build and Release

The project includes automated build and release via GitHub Actions:

### Supported Architectures
- **Linux**: x86_64, aarch64, arm, i386

### Binary Naming Convention
Binaries follow the pattern: `pkagent-linux-{arch}`
- `pkagent-linux-x86_64` - Linux Intel/AMD 64-bit
- `pkagent-linux-aarch64` - Linux ARM 64-bit
- `pkagent-linux-arm` - Linux ARM 32-bit
- `pkagent-linux-i386` - Linux Intel 32-bit

### Release Process
1. **Tag a release**: `git tag v1.0.0 && git push origin v1.0.0`
2. **GitHub Actions builds** all architectures automatically
3. **Creates GitHub release** with all binaries and checksums
4. **Binaries are ready** for PubliKey server distribution

### Manual Building
```bash
make build-all                    # Build for all platforms
make checksums                    # Generate SHA256 checksums
make release                      # Full release build with tests
```

## Server Integration

The PubliKey server should implement the installation flow for production:

1. **Host the binary** at `/downloads/pkagent-linux-{arch}`
2. **Generate installation scripts** dynamically with templated tokens/endpoints via URL parameters
3. **Provide one-command installation** with pre-configured settings
4. **Handle architecture detection** and serve appropriate binaries
5. **Include error handling** for platform compatibility and download failures

Example server implementation:
```bash
# User visits: https://your-server.com/install.sh?token=pk_abc123
# Server templates an installation script with the user's token and endpoint
# User runs: curl -sSL <URL> | sudo bash
# Script downloads the binary and uses built-in installer
```
# PubliKey Agent

A Go implementation of the PubliKey agent that manages SSH key deployments on remote hosts. The agent communicates with the PubliKey SSH Key Management Platform to automatically deploy and manage SSH keys for users.

## Features

- **Dual Mode Operation**: Run in system mode (manages all users) or user mode (current user only)
- **Continuous Service**: Runs as a systemd service with automatic restart capabilities
- **SSH Config Analysis**: Intelligently parses `sshd_config` to find all authorized_keys locations
- **Dry Run Mode**: Test deployments without making actual changes
- **User Filtering**: Include/exclude specific users from management
- **Robust Error Handling**: Exponential backoff for API requests and graceful failure recovery
- **Security Focused**: Proper file permissions, key validation, and privilege separation

## Quick Start

### System-wide Installation (requires sudo)

```bash
# Download and run the installer with your pre-configured token
curl -sSL https://your-publikey-server.com/install.sh?token=pk_your_token | sudo bash

# Check service status
sudo systemctl status pkagent
```

### User Installation

```bash
# Download and run the installer in user mode
curl -sSL https://your-publikey-server.com/install.sh?token=pk_your_token | bash -s -- --user-mode

# Check service status
systemctl --user status pkagent
```

### Manual Installation (for development)

```bash
# Download the binary directly
curl -L -o pkagent https://your-publikey-server.com/downloads/pkagent-linux-x86_64
chmod +x pkagent

# Install as system service
sudo ./pkagent install --token=pk_your_token --endpoint=https://your-publikey-server.com

# Or install as user service
./pkagent install --token=pk_your_token --endpoint=https://your-publikey-server.com --user-mode
```

## Usage

### Command Line Options

```bash
./pkagent [options]

Options:
  --token=TOKEN           Agent authentication token (required)
  --endpoint=ENDPOINT     API endpoint URL (required)
  --user-mode            Run in user mode (manage only current user)
  --dry-run              Test mode - no actual changes made
  --include-users=LIST   Comma-separated list of users to manage
  --exclude-users=LIST   Comma-separated list of users to exclude
  --report-interval=5m   How often to report system info
  --key-check-interval=1m How often to check for key updates
  --log-level=info       Log level (debug, info, warn, error)
  --version              Show version and exit
```

### Environment Variables

You can also configure the agent using environment variables:

```bash
export PUBLIKEY_TOKEN="pk_your_token_here"
export PUBLIKEY_ENDPOINT="https://your-domain.com"
./pkagent --user-mode
```

### Examples

```bash
# Run in system mode with dry-run
./pkagent --token=pk_abc123 --endpoint=https://demo.publikey.io --dry-run

# Run in user mode for current user only
./pkagent --token=pk_abc123 --endpoint=https://demo.publikey.io --user-mode

# Manage only specific users
./pkagent --token=pk_abc123 --endpoint=https://demo.publikey.io --include-users=john,jane

# Exclude system users
./pkagent --token=pk_abc123 --endpoint=https://demo.publikey.io --exclude-users=root,daemon
```

## Development

### Prerequisites

- Go 1.24 or later
- Make (for build automation)

### Building

```bash
# Format, vet, test, and build
make dev

# Build only
make build

# Build for all platforms
make release
```

### Testing

```bash
# Run tests
make test

# Test with dry-run mode
make dry-run TOKEN=pk_test_token ENDPOINT=https://demo.publikey.io
```

### Version Management

```bash
# Check current version
./version.sh get

# Bump version
./version.sh bump patch   # 0.6.0 -> 0.6.1
./version.sh bump minor   # 0.6.0 -> 0.7.0
./version.sh bump major   # 0.6.0 -> 1.0.0

# Set specific version
./version.sh set 1.2.3
```

## System Requirements

### Supported Platforms

- Linux (x86_64, ARM64)
- macOS (x86_64, ARM64)

### Runtime Requirements

- systemd (for service management)
- Access to `/etc/passwd` and `/etc/ssh/sshd_config` (system mode)
- Write access to user home directories

### Permissions

- **System Mode**: Requires root privileges to manage all users
- **User Mode**: Runs with current user privileges, manages only that user

## Configuration

### SSH Configuration Analysis

The agent automatically analyzes the SSH daemon configuration to find authorized_keys locations:

1. Parses `/etc/ssh/sshd_config` for `AuthorizedKeysFile` directives
2. Supports token replacement (`%h` for home directory, `%u` for username)
3. Falls back to default `~/.ssh/authorized_keys` if no configuration found
4. Manages multiple authorized_keys files if configured

### Key Management

- Preserves existing non-PubliKey managed keys
- Adds PubliKey managed keys with identifying comments
- Maintains proper file permissions (700 for .ssh, 600 for authorized_keys)
- Sets correct ownership for all managed files

## Service Management

### System Service

```bash
# Status and control
sudo systemctl status pkagent
sudo systemctl start pkagent
sudo systemctl stop pkagent
sudo systemctl restart pkagent

# Logs
sudo journalctl -u pkagent -f
```

### User Service

```bash
# Status and control
systemctl --user status pkagent
systemctl --user start pkagent
systemctl --user stop pkagent
systemctl --user restart pkagent

# Logs
journalctl --user -u pkagent -f
```

### Service Configuration

The agent creates systemd service files with:

- Automatic restart on failure
- Proper dependency ordering (after network)
- Security hardening settings
- Structured logging

## API Integration

The agent communicates with the PubliKey API using the following endpoints:

- `POST /api/agent/report` - Report system information and users
- `GET /api/host/keys` - Retrieve SSH key assignments
- `GET /api/health` - Health check (optional)

Authentication uses Bearer tokens with the format `pk_*`.

## Security Considerations

- **Token Security**: Store agent tokens securely, rotate regularly
- **File Permissions**: Agent maintains correct SSH file permissions
- **Privilege Separation**: Use user mode when possible
- **Key Validation**: All SSH keys are validated before deployment
- **Audit Trail**: All operations are logged for auditing

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure the agent has appropriate privileges for the mode it's running in
2. **Network Errors**: Check firewall settings and endpoint URL
3. **Invalid Token**: Verify the agent token is correct and active
4. **User Not Found**: Ensure users exist on the system before assignments

### Debug Mode

Enable debug logging for detailed operation information:

```bash
./pkagent --log-level=debug --token=pk_abc123 --endpoint=https://demo.publikey.io --dry-run
```

### Log Locations

- **System Mode**: `journalctl -u pkagent`
- **User Mode**: `journalctl --user -u pkagent`
- **Manual Run**: stdout/stderr

## Server Integration

For production deployments, the PubliKey server should serve installation scripts with baked-in configuration:

```bash
# The server generates install scripts with embedded tokens
# Example URL: https://your-server.com/install.sh?token=pk_abc123&endpoint=https://your-server.com
# This allows one-command installation: curl -sSL <URL> | sudo bash
```

The server should:
1. Host the binary downloads at `/downloads/pkagent-linux-{arch}`
2. Generate installation scripts at `/install.sh` with query parameters
3. Template the script with user-specific tokens and configuration
4. The script downloads the binary and uses the built-in installer

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`make test`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

- Documentation: [GitHub Wiki](https://github.com/gopublikey/agent/wiki)
- Issues: [GitHub Issues](https://github.com/gopublikey/agent/issues)
- Discussions: [GitHub Discussions](https://github.com/gopublikey/agent/discussions)
# PubliKey API Documentation

This document describes the REST API endpoints available in the PubliKey SSH Key Management Platform. This documentation is designed to enable implementation of a PubliKey agent that can manage SSH key deployments on remote hosts.

## Overview

PubliKey is an SSH Public Key Management Platform that allows centralized management of SSH key deployments across multiple hosts. Agents installed on target hosts communicate with the PubliKey server to:

1. **Report system information and users** - Keep the server updated about host state
2. **Retrieve key assignments** - Get SSH keys that should be deployed to specific users
3. **Authenticate securely** - Use pre-shared agent tokens for secure communication

## Base URL

All API endpoints are relative to your application's base URL:
```
https://your-domain.com/api
```

## Authentication

Most endpoints require authentication via Bearer tokens. Agents authenticate using their assigned agent tokens with the format `pk_*`.

### Agent Authentication
```
Authorization: Bearer pk_your_agent_token_here
```

## Agent Implementation Overview

A PubliKey agent should implement the following core functionality:

### 1. **System Discovery**
- Detect operating system, architecture, and distribution
- Enumerate system users (including UIDs, shells, home directories)
- Identify SSH daemon configuration (port, status)

### 2. **Periodic Reporting**
- Send system information and user lists to `/api/agent/report`
- Recommended interval: 5-15 minutes for user updates, 1-6 hours for system info
- Handle authentication errors gracefully

### 3. **Key Management**
- Retrieve key assignments from `/api/host/keys`
- Deploy SSH keys to appropriate user `~/.ssh/authorized_keys` files
- Handle key additions, removals, and updates
- Maintain proper file permissions (600 for authorized_keys, 700 for .ssh directory)

### 4. **Error Handling**
- Retry failed API requests with exponential backoff
- Log all operations for debugging
- Gracefully handle network connectivity issues
- Validate SSH key formats before deployment

### 5. **Security Considerations**
- Store agent token securely
- Validate all SSH keys before deployment
- Maintain audit logs of key deployments
- Run with minimal required privileges

## Endpoints

### 1. Health Check

**GET** `/api/health`

Returns the health status of the API service.

#### Request
No authentication required.

#### Response
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00.000Z",
  "service": "publikey-api"
}
```

#### Status Codes
- `200` - Service is healthy

---

### 2. Agent System Information Report

**POST** `/api/agent/report`

Allows agents to report their system information and user lists to the server.

#### Authentication
Required. Agent must authenticate with a valid agent token.

#### Request Body
```json
{
  "hostname": "server.example.com",
  "systemInfo": {
    "os": "Linux",
    "arch": "x86_64",
    "platform": "linux",
    "kernel": "5.4.0-74-generic",
    "distribution": "Ubuntu",
    "version": "20.04.2 LTS",
    "sshPort": 22
  },
  "agentVersion": "0.6.0",
  "users": [
    {
      "username": "john",
      "uid": 1001,
      "shell": "/bin/bash",
      "home_dir": "/home/john",
      "disabled": false
    },
    {
      "username": "jane",
      "uid": 1002,
      "shell": "/bin/zsh",
      "home_dir": "/home/jane",
      "disabled": false
    }
  ]
}
```

#### Request Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `hostname` | string | Yes | The hostname of the reporting system |
| `systemInfo` | object | Yes | System information object |
| `systemInfo.os` | string | Yes | Operating system name |
| `systemInfo.arch` | string | Yes | System architecture (e.g., x86_64, arm64) |
| `systemInfo.platform` | string | Yes | Platform identifier (e.g., linux, darwin) |
| `systemInfo.kernel` | string | Yes | Kernel version |
| `systemInfo.distribution` | string | Yes | OS distribution name |
| `systemInfo.version` | string | Yes | OS version |
| `systemInfo.sshPort` | number | No | SSH port (defaults to 22) |
| `agentVersion` | string | Yes | Version of the reporting agent |
| `users` | array | Yes | Array of user objects |
| `users[].username` | string | Yes | Username |
| `users[].uid` | number | Yes | User ID |
| `users[].shell` | string | No | User's shell |
| `users[].home_dir` | string | No | User's home directory |
| `users[].disabled` | boolean | No | Whether the user is disabled |

#### Success Response
```json
{
  "success": true,
  "hostId": "cm123456789",
  "message": "Host data processed successfully",
  "usersProcessed": 2,
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

#### Error Responses

**401 Unauthorized**
```json
{
  "success": false,
  "error": "Authentication failed",
  "message": "Invalid or expired token",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

**405 Method Not Allowed**
```json
{
  "success": false,
  "error": "Host deactivated",
  "message": "This host has been deactivated and cannot report data",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

**400 Bad Request**
```json
{
  "success": false,
  "error": "Invalid request",
  "message": "Missing required fields: hostname, systemInfo, agentVersion, users",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

**426 Upgrade Required**
```json
{
  "error": "Agent version too old",
  "message": "Please update your agent to the latest version",
  "minimumVersion": "0.6.0",
  "currentVersion": "0.5.9",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

**500 Internal Server Error**
```json
{
  "success": false,
  "error": "Internal server error",
  "message": "Failed to process agent report",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

---

### 3. SSH Key Assignments

**GET** `/api/host/keys`

Retrieves SSH key assignments for the authenticated host.

#### Authentication
Required. Agent must authenticate with a valid agent token.

#### Request
No request body required.

#### Success Response
```json
{
  "success": true,
  "hostId": "cm123456789",
  "hostname": "server.example.com",
  "assignments": [
    {
      "username": "john",
      "fingerprint": "SHA256:abc123def456ghi789jkl012mno345pqr678stu901vwx234yz",
      "publicKey": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...",
      "keyType": "ssh-rsa",
      "comment": "john@laptop",
      "usePrimaryKey": true,
      "assignmentId": "cm987654321",
      "keySource": "user"
    },
    {
      "username": "deploy",
      "fingerprint": "SHA256:def456ghi789jkl012mno345pqr678stu901vwx234yzabc123",
      "publicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq...",
      "keyType": "ssh-ed25519",
      "comment": "CI/CD Deploy Key",
      "usePrimaryKey": false,
      "assignmentId": "cm876543210",
      "keySource": "system",
      "purpose": "CI/CD deployment"
    },
    {
      "username": "team-dev",
      "fingerprint": "SHA256:ghi789jkl012mno345pqr678stu901vwx234yzabc123def456",
      "publicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHr...",
      "keyType": "ssh-ed25519",
      "comment": "Team Development Key",
      "usePrimaryKey": false,
      "assignmentId": "cm765432109",
      "keySource": "team",
      "purpose": "Development access"
    }
  ],
  "stats": {
    "originalCount": 3,
    "deduplicatedCount": 3,
    "duplicatesRemoved": 0,
    "deduplicationApplied": false,
    "userKeyAssignments": 1,
    "systemKeyAssignments": 1,
    "teamKeyAssignments": 1,
    "totalAssignments": 3
  },
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

#### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `success` | boolean | Whether the request was successful |
| `hostId` | string | Unique identifier of the host |
| `hostname` | string | Hostname of the system |
| `assignments` | array | Array of key assignment objects |
| `assignments[].username` | string | Target username for the key |
| `assignments[].fingerprint` | string | SSH key fingerprint |
| `assignments[].publicKey` | string | Full SSH public key |
| `assignments[].keyType` | string | Type of SSH key (ssh-rsa, ssh-ed25519, etc.) |
| `assignments[].comment` | string \| null | Key comment/description |
| `assignments[].usePrimaryKey` | boolean | Whether this is a primary key assignment |
| `assignments[].assignmentId` | string | Unique assignment identifier |
| `assignments[].keySource` | string | Source of the key ('user', 'system', or 'team') |
| `assignments[].purpose` | string | Purpose description (for system/team keys) |
| `stats` | object | Assignment statistics |
| `stats.originalCount` | number | Original number of assignments before deduplication |
| `stats.deduplicatedCount` | number | Final number of assignments after deduplication |
| `stats.duplicatesRemoved` | number | Number of duplicate assignments removed |
| `stats.deduplicationApplied` | boolean | Whether deduplication was performed |
| `stats.userKeyAssignments` | number | Count of user key assignments |
| `stats.systemKeyAssignments` | number | Count of system key assignments |
| `stats.teamKeyAssignments` | number | Count of team key assignments |
| `stats.totalAssignments` | number | Total final assignment count |

#### Error Responses

**401 Unauthorized**
```json
{
  "success": false,
  "error": "Authentication failed",
  "message": "Invalid or expired token",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

**405 Method Not Allowed**
```json
{
  "success": false,
  "error": "Host deactivated",
  "message": "This host has been deactivated and cannot retrieve key assignments",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

**500 Internal Server Error**
```json
{
  "success": false,
  "error": "Internal server error",
  "message": "Failed to retrieve SSH key assignments",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

---

### 4. Authentication Endpoints

**GET/POST** `/api/auth/[...all]`

Handles all authentication-related requests via Better Auth. These endpoints manage user sessions, OAuth providers, and authentication flows.

#### Authentication
Varies by endpoint. Some endpoints require existing authentication, others are used for initial authentication.

#### Common Endpoints

- `GET /api/auth/session` - Get current session
- `POST /api/auth/signin` - Sign in with credentials
- `POST /api/auth/signup` - Create new account
- `POST /api/auth/signout` - Sign out current session
- `GET /api/auth/providers` - List available OAuth providers
- `GET /api/auth/oauth/[provider]` - OAuth provider redirect
- `POST /api/auth/oauth/callback/[provider]` - OAuth callback handler

#### Note
These endpoints are managed by Better Auth. Refer to the [Better Auth documentation](https://better-auth.com) for detailed request/response formats and authentication flows.

---

### 5. Dynamic Install Script

**GET** `/install.sh`

Generates a customized installation script for the PubliKey agent with pre-configured parameters.

#### Authentication
No authentication required.

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | string | Yes | Agent token for authentication |
| `endpoint` | string | No | API endpoint URL (defaults to BETTER_AUTH_URL env var) |

#### Example Request
```
GET /install.sh?token=pk_abc123def456&endpoint=https://your-domain.com
```

#### Response
Returns a bash script with the provided parameters baked in:

```bash
#!/bin/bash

# PubliKey Agent Installation Script
# Generated: 2024-01-01T12:00:00.000Z

set -e

AGENT_TOKEN="pk_abc123def456"
API_ENDPOINT="https://your-domain.com"

# ... rest of installation script
```

#### Content-Type
`text/plain; charset=utf-8`

#### Usage Examples

**Using curl:**
```bash
curl "https://your-domain.com/install.sh?token=pk_abc123def456" | sudo bash
```

**Using wget:**
```bash
wget -qO- "https://your-domain.com/install.sh?token=pk_abc123def456" | sudo bash
```

#### Error Responses

**400 Bad Request**
```bash
#!/bin/bash
echo "Error: Missing required token parameter"
exit 1
```

## Error Handling

All API endpoints follow consistent error response patterns:

1. **HTTP Status Codes** indicate the general category of error
2. **JSON Response Bodies** provide detailed error information
3. **Timestamps** are included in ISO 8601 format
4. **Error Messages** are human-readable and actionable

### Common Status Codes

- `200` - Success
- `400` - Bad Request (invalid parameters or missing required fields)
- `401` - Unauthorized (invalid or missing authentication)
- `405` - Method Not Allowed (often used for deactivated resources)
- `426` - Upgrade Required (agent version too old)
- `500` - Internal Server Error

## Rate Limiting

Currently, no explicit rate limiting is implemented. However, agents should implement reasonable request intervals to avoid overwhelming the server.

## Agent Implementation Guide

### Basic Agent Workflow

```
1. Start agent with configuration (token, endpoint)
2. Perform initial system discovery
3. Send initial report to /api/agent/report
4. Enter main loop:
   a. Retrieve key assignments from /api/host/keys
   b. Compare with current deployed keys
   c. Deploy new/updated keys
   d. Remove expired/revoked keys
   e. Send periodic system update to /api/agent/report
   f. Sleep for configured interval
   g. Repeat
```

### Configuration Requirements

An agent needs the following configuration:

```json
{
  "agentToken": "pk_abc123def456ghi789",
  "apiEndpoint": "https://your-domain.com",
  "reportInterval": 300,
  "keyCheckInterval": 60,
  "logLevel": "info",
  "sshKeysPath": "/home/{username}/.ssh/authorized_keys",
  "backupKeys": true,
  "dryRun": false
}
```

### System Information Collection

The agent must collect and report the following system information:

#### Operating System Detection
```bash
# Examples for different systems:

# Linux - /etc/os-release
PRETTY_NAME="Ubuntu 20.04.2 LTS"
VERSION_ID="20.04"
ID=ubuntu

# macOS - sw_vers
ProductName: macOS
ProductVersion: 12.6
BuildVersion: 21G115

# FreeBSD - uname + /etc/os-release
FreeBSD 13.1-RELEASE
```

#### Architecture Detection
```bash
# Use uname -m
x86_64, arm64, aarch64, i386, etc.
```

#### User Enumeration
```bash
# Parse /etc/passwd for user information
username:x:uid:gid:comment:home:shell

# Example extraction:
john:x:1001:1001:John Doe:/home/john:/bin/bash
jane:x:1002:1002:Jane Smith:/home/jane:/bin/zsh
```

#### SSH Port Detection
```bash
# Check sshd_config for Port directive
grep "^Port" /etc/ssh/sshd_config

# Check if SSH service is running
systemctl is-active ssh
service ssh status
```

### Key Deployment Process

#### 1. Authorized Keys File Management

```bash
# File locations
~/.ssh/authorized_keys          # Primary location
~/.ssh/authorized_keys2         # Legacy fallback

# Required permissions
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

#### 2. Key Format Validation

Validate SSH public keys before deployment:

```regex
# SSH key format patterns
ssh-rsa AAAA[0-9A-Za-z+/]+[=]{0,3}( .*)?
ssh-dss AAAA[0-9A-Za-z+/]+[=]{0,3}( .*)?
ssh-ed25519 AAAA[0-9A-Za-z+/]+[=]{0,3}( .*)?
ecdsa-sha2-nistp256 AAAA[0-9A-Za-z+/]+[=]{0,3}( .*)?
ecdsa-sha2-nistp384 AAAA[0-9A-Za-z+/]+[=]{0,3}( .*)?
ecdsa-sha2-nistp521 AAAA[0-9A-Za-z+/]+[=]{0,3}( .*)?
```

#### 3. Key Deployment Strategy

```python
# Pseudocode for key deployment
def deploy_keys_for_user(username, assigned_keys):
    user_info = get_user_info(username)
    if not user_info.exists:
        log_warning(f"User {username} does not exist, skipping")
        return
    
    ssh_dir = f"{user_info.home}/.ssh"
    authorized_keys_file = f"{ssh_dir}/authorized_keys"
    
    # Create .ssh directory if it doesn't exist
    ensure_directory(ssh_dir, mode=0o700, owner=user_info.uid, group=user_info.gid)
    
    # Read current authorized_keys
    current_keys = read_authorized_keys(authorized_keys_file)
    
    # Build new authorized_keys content
    new_keys = []
    for assignment in assigned_keys:
        if assignment.usePrimaryKey:
            # Primary keys get precedence and special handling
            key_line = f"{assignment.publicKey}"
        else:
            # Specific assignment keys may have restrictions
            key_line = f"{assignment.publicKey}"
        
        # Add comment with PubliKey metadata
        key_line += f" # PubliKey:{assignment.assignmentId}:{assignment.keySource}"
        new_keys.append(key_line)
    
    # Preserve non-PubliKey managed keys
    preserved_keys = [key for key in current_keys if not "# PubliKey:" in key]
    
    # Combine and write
    all_keys = preserved_keys + new_keys
    write_authorized_keys(authorized_keys_file, all_keys, user_info.uid, user_info.gid)
```

### Error Handling and Retry Logic

#### Exponential Backoff for API Requests

```python
import time
import random

def make_api_request_with_retry(url, data=None, max_retries=5):
    for attempt in range(max_retries):
        try:
            response = make_request(url, data)
            if response.status_code == 200:
                return response
            elif response.status_code in [401, 405]:
                # Don't retry auth failures or deactivated hosts
                raise AuthenticationError("Invalid token or deactivated host")
            elif response.status_code >= 500:
                # Server errors - retry with backoff
                if attempt < max_retries - 1:
                    delay = (2 ** attempt) + random.uniform(0, 1)
                    time.sleep(delay)
                    continue
            else:
                # Client errors - don't retry
                raise ClientError(f"Request failed: {response.status_code}")
        except NetworkError:
            if attempt < max_retries - 1:
                delay = (2 ** attempt) + random.uniform(0, 1)
                time.sleep(delay)
                continue
            raise
    
    raise MaxRetriesExceeded("Failed after maximum retries")
```

### Logging and Monitoring

#### Required Log Events

```
[INFO] Agent started, version: 0.6.0
[INFO] System info: Ubuntu 20.04.2 LTS, x86_64
[INFO] Discovered 15 users on system
[INFO] Reported system info to server successfully
[INFO] Retrieved 8 key assignments for 3 users
[INFO] Deployed 2 new keys for user 'john'
[INFO] Removed 1 expired key for user 'jane'
[WARN] User 'deploy' not found on system, skipping assignments
[ERROR] Failed to retrieve key assignments: HTTP 500
[ERROR] Invalid SSH key format for assignment abc123: ssh-rsa invalid_key_data
```

#### Metrics to Track

- Number of users managed
- Number of keys deployed/removed per cycle
- API request success/failure rates
- Key deployment success/failure rates
- System resource usage

### Sample Agent Implementations

#### Bash Implementation Skeleton

```bash
#!/bin/bash

# PubliKey Agent - Bash Implementation
set -euo pipefail

AGENT_TOKEN="${AGENT_TOKEN:-}"
API_ENDPOINT="${API_ENDPOINT:-}"
REPORT_INTERVAL="${REPORT_INTERVAL:-300}"
KEY_CHECK_INTERVAL="${KEY_CHECK_INTERVAL:-60}"

# Function to get system info
get_system_info() {
    local os_info
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        echo "{\"os\":\"$(uname -s)\",\"arch\":\"$(uname -m)\",\"platform\":\"$(uname -s | tr '[:upper:]' '[:lower:]')\",\"kernel\":\"$(uname -r)\",\"distribution\":\"$ID\",\"version\":\"$VERSION_ID\"}"
    fi
}

# Function to get users
get_users() {
    local users_json="["
    local first=true
    
    while IFS=: read -r username _ uid gid _ home shell; do
        [[ $uid -lt 65534 ]] || continue  # Skip nobody/nogroup
        
        if [[ $first == true ]]; then
            first=false
        else
            users_json+=","
        fi
        
        users_json+="{\"username\":\"$username\",\"uid\":$uid,\"shell\":\"$shell\",\"home_dir\":\"$home\"}"
    done < /etc/passwd
    
    users_json+="]"
    echo "$users_json"
}

# Function to report to server
report_to_server() {
    local hostname=$(hostname)
    local system_info=$(get_system_info)
    local users=$(get_users)
    local agent_version="0.6.0"
    
    local payload=$(cat <<EOF
{
    "hostname": "$hostname",
    "systemInfo": $system_info,
    "agentVersion": "$agent_version",
    "users": $users
}
EOF
)
    
    curl -s -X POST \
        -H "Authorization: Bearer $AGENT_TOKEN" \
        -H "Content-Type: application/json" \
        -d "$payload" \
        "$API_ENDPOINT/api/agent/report"
}

# Function to get key assignments
get_key_assignments() {
    curl -s -H "Authorization: Bearer $AGENT_TOKEN" \
        "$API_ENDPOINT/api/host/keys"
}

# Function to deploy keys for a user
deploy_user_keys() {
    local username="$1"
    local keys_json="$2"
    
    # Implementation for key deployment
    # ... (detailed implementation)
}

# Main agent loop
main() {
    echo "[INFO] PubliKey Agent starting..."
    
    while true; do
        echo "[INFO] Reporting system information..."
        if report_to_server; then
            echo "[INFO] System report successful"
        else
            echo "[ERROR] System report failed"
        fi
        
        echo "[INFO] Retrieving key assignments..."
        local assignments=$(get_key_assignments)
        if [[ $? -eq 0 ]]; then
            echo "[INFO] Processing key assignments..."
            # Process assignments
            # ... (detailed implementation)
        else
            echo "[ERROR] Failed to retrieve key assignments"
        fi
        
        sleep "$KEY_CHECK_INTERVAL"
    done
}

# Run main function
main "$@"
```

#### Python Implementation Skeleton

```python
#!/usr/bin/env python3

import time
import json
import requests
import pwd
import os
import platform
import logging
from pathlib import Path
from typing import Dict, List, Optional

class PubliKeyAgent:
    def __init__(self, config: Dict):
        self.token = config['agentToken']
        self.endpoint = config['apiEndpoint']
        self.report_interval = config.get('reportInterval', 300)
        self.key_check_interval = config.get('keyCheckInterval', 60)
        self.version = "0.6.0"
        
        # Setup logging
        logging.basicConfig(
            level=getattr(logging, config.get('logLevel', 'INFO').upper()),
            format='%(asctime)s [%(levelname)s] %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def get_system_info(self) -> Dict:
        """Collect system information"""
        system_info = {
            'os': platform.system(),
            'arch': platform.machine(),
            'platform': platform.system().lower(),
            'kernel': platform.release(),
        }
        
        # Get distribution info
        try:
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release') as f:
                    os_release = {}
                    for line in f:
                        if '=' in line:
                            key, value = line.strip().split('=', 1)
                            os_release[key] = value.strip('"')
                    
                    system_info['distribution'] = os_release.get('ID', 'unknown')
                    system_info['version'] = os_release.get('VERSION_ID', 'unknown')
        except Exception as e:
            self.logger.warning(f"Could not read OS release info: {e}")
            system_info['distribution'] = 'unknown'
            system_info['version'] = 'unknown'
        
        # Detect SSH port
        try:
            ssh_port = 22  # default
            if os.path.exists('/etc/ssh/sshd_config'):
                with open('/etc/ssh/sshd_config') as f:
                    for line in f:
                        if line.strip().startswith('Port '):
                            ssh_port = int(line.strip().split()[1])
                            break
            system_info['sshPort'] = ssh_port
        except Exception as e:
            self.logger.warning(f"Could not detect SSH port: {e}")
        
        return system_info
    
    def get_users(self) -> List[Dict]:
        """Enumerate system users"""
        users = []
        try:
            for user in pwd.getpwall():
                # Skip system users below UID 1000 (except root)
                if user.pw_uid < 1000 and user.pw_uid != 0:
                    continue
                
                users.append({
                    'username': user.pw_name,
                    'uid': user.pw_uid,
                    'shell': user.pw_shell,
                    'home_dir': user.pw_dir,
                    'disabled': False  # Would need additional logic to detect
                })
        except Exception as e:
            self.logger.error(f"Error enumerating users: {e}")
        
        return users
    
    def report_to_server(self) -> bool:
        """Send system report to server"""
        try:
            payload = {
                'hostname': platform.node(),
                'systemInfo': self.get_system_info(),
                'agentVersion': self.version,
                'users': self.get_users()
            }
            
            response = requests.post(
                f"{self.endpoint}/api/agent/report",
                json=payload,
                headers={'Authorization': f'Bearer {self.token}'},
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                self.logger.info(f"System report successful: {result.get('message', '')}")
                return True
            else:
                self.logger.error(f"System report failed: {response.status_code} {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"System report error: {e}")
            return False
    
    def get_key_assignments(self) -> Optional[Dict]:
        """Retrieve key assignments from server"""
        try:
            response = requests.get(
                f"{self.endpoint}/api/host/keys",
                headers={'Authorization': f'Bearer {self.token}'},
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                self.logger.error(f"Key assignment retrieval failed: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"Key assignment retrieval error: {e}")
            return None
    
    def deploy_keys_for_user(self, username: str, assignments: List[Dict]) -> bool:
        """Deploy SSH keys for a specific user"""
        try:
            # Get user info
            try:
                user_info = pwd.getpwnam(username)
            except KeyError:
                self.logger.warning(f"User {username} not found, skipping")
                return False
            
            ssh_dir = Path(user_info.pw_dir) / '.ssh'
            authorized_keys_file = ssh_dir / 'authorized_keys'
            
            # Create .ssh directory if needed
            ssh_dir.mkdir(mode=0o700, exist_ok=True)
            os.chown(ssh_dir, user_info.pw_uid, user_info.pw_gid)
            
            # Read current authorized_keys
            current_keys = []
            if authorized_keys_file.exists():
                current_keys = authorized_keys_file.read_text().splitlines()
            
            # Filter out PubliKey-managed keys
            preserved_keys = [key for key in current_keys if '# PubliKey:' not in key]
            
            # Add new PubliKey-managed keys
            new_keys = []
            for assignment in assignments:
                key_line = assignment['publicKey']
                metadata = f"# PubliKey:{assignment['assignmentId']}:{assignment['keySource']}"
                new_keys.append(f"{key_line} {metadata}")
            
            # Write updated authorized_keys
            all_keys = preserved_keys + new_keys
            authorized_keys_file.write_text('\n'.join(all_keys) + '\n')
            authorized_keys_file.chmod(0o600)
            os.chown(authorized_keys_file, user_info.pw_uid, user_info.pw_gid)
            
            self.logger.info(f"Deployed {len(new_keys)} keys for user {username}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error deploying keys for user {username}: {e}")
            return False
    
    def process_key_assignments(self, assignments_data: Dict) -> None:
        """Process and deploy key assignments"""
        assignments = assignments_data.get('assignments', [])
        
        # Group assignments by username
        user_assignments = {}
        for assignment in assignments:
            username = assignment['username']
            if username not in user_assignments:
                user_assignments[username] = []
            user_assignments[username].append(assignment)
        
        # Deploy keys for each user
        for username, user_keys in user_assignments.items():
            self.deploy_keys_for_user(username, user_keys)
    
    def run(self) -> None:
        """Main agent loop"""
        self.logger.info(f"PubliKey Agent {self.version} starting...")
        
        last_report_time = 0
        
        while True:
            try:
                current_time = time.time()
                
                # Send periodic system report
                if current_time - last_report_time >= self.report_interval:
                    if self.report_to_server():
                        last_report_time = current_time
                
                # Process key assignments
                assignments_data = self.get_key_assignments()
                if assignments_data:
                    self.process_key_assignments(assignments_data)
                
                time.sleep(self.key_check_interval)
                
            except KeyboardInterrupt:
                self.logger.info("Agent stopped by user")
                break
            except Exception as e:
                self.logger.error(f"Unexpected error in main loop: {e}")
                time.sleep(60)  # Wait before retrying

def main():
    # Example configuration
    config = {
        'agentToken': os.environ.get('PUBLIKEY_TOKEN'),
        'apiEndpoint': os.environ.get('PUBLIKEY_ENDPOINT'),
        'reportInterval': int(os.environ.get('PUBLIKEY_REPORT_INTERVAL', '300')),
        'keyCheckInterval': int(os.environ.get('PUBLIKEY_KEY_CHECK_INTERVAL', '60')),
        'logLevel': os.environ.get('PUBLIKEY_LOG_LEVEL', 'INFO')
    }
    
    if not config['agentToken'] or not config['apiEndpoint']:
        print("Error: PUBLIKEY_TOKEN and PUBLIKEY_ENDPOINT environment variables required")
        exit(1)
    
    agent = PubliKeyAgent(config)
    agent.run()

if __name__ == '__main__':
    main()
```

## Security Considerations

1. **Agent Tokens** should be kept secure and rotated regularly
2. **HTTPS** must be used for all communications in production
3. **IP Whitelisting** may be implemented at the infrastructure level
4. **Request Validation** is performed on all endpoints to prevent injection attacks
5. **Audit Logging** tracks all key assignment and system changes
6. **SSH Key Validation** must be performed before deployment
7. **File Permissions** must be maintained correctly (700 for .ssh, 600 for authorized_keys)
8. **User Privilege Separation** - agents should run with minimal required privileges
9. **Backup and Recovery** - consider backing up authorized_keys before modifications

## Client IP Detection

The API automatically detects client IP addresses from common proxy headers:
- `X-Forwarded-For`
- `X-Real-IP`
- `CF-Connecting-IP` (Cloudflare)
- `X-Client-IP`
- `X-Forwarded`

This information is used for audit logging and host tracking.

## Testing and Validation

### API Testing

Test API endpoints with curl:

```bash
# Test health endpoint
curl -X GET https://your-domain.com/api/health

# Test agent report (replace with your token)
curl -X POST https://your-domain.com/api/agent/report \
  -H "Authorization: Bearer pk_your_token_here" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "test-host",
    "systemInfo": {
      "os": "Linux",
      "arch": "x86_64",
      "platform": "linux",
      "kernel": "5.4.0-74-generic",
      "distribution": "ubuntu",
      "version": "20.04"
    },
    "agentVersion": "0.6.0",
    "users": [
      {
        "username": "testuser",
        "uid": 1001,
        "shell": "/bin/bash",
        "home_dir": "/home/testuser"
      }
    ]
  }'

# Test key retrieval
curl -X GET https://your-domain.com/api/host/keys \
  -H "Authorization: Bearer pk_your_token_here"
```

### Agent Testing

1. **Dry Run Mode** - Test without actually modifying authorized_keys files
2. **Unit Tests** - Test individual functions (system info collection, user enumeration)
3. **Integration Tests** - Test against a PubliKey development server
4. **Permission Tests** - Verify correct file ownership and permissions
5. **Error Handling Tests** - Test behavior with network failures, invalid tokens, etc.
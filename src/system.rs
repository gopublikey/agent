use serde::Serialize;
use sysinfo::System;
use anyhow::Result;
use tracing::{debug, warn};
use std::fs;

#[derive(Serialize, Debug)]
pub struct SystemInfo {
    pub os: String,
    pub arch: String,
    pub platform: String,
    pub kernel: String,
    pub distribution: String,
    pub version: String,
    #[serde(rename = "sshPort")]
    pub ssh_port: Option<u16>,
}


#[cfg(target_os = "linux")]
fn get_linux_distribution() -> Option<String> {
    use std::fs;
    
    // Try /etc/os-release first
    if let Ok(content) = fs::read_to_string("/etc/os-release") {
        for line in content.lines() {
            if line.starts_with("NAME=") {
                return Some(line[5..].trim_matches('"').to_string());
            }
        }
    }

    // Fallback to /etc/issue
    if let Ok(content) = fs::read_to_string("/etc/issue") {
        return Some(content.lines().next()?.trim().to_string());
    }

    None
}

fn detect_ssh_port() -> Option<u16> {
    // Default SSH port
    let mut port = 22u16;
    
    // Try to read sshd_config to find custom port
    let sshd_config_paths = [
        "/etc/ssh/sshd_config",
        "/etc/sshd_config", 
        "/usr/local/etc/ssh/sshd_config",
    ];
    
    for config_path in &sshd_config_paths {
        if let Ok(content) = fs::read_to_string(config_path) {
            debug!("Reading SSH config from: {}", config_path);
            
            for line in content.lines() {
                let line = line.trim();
                
                // Skip comments and empty lines
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                
                // Look for Port directive
                if let Some(port_line) = line.strip_prefix("Port ") {
                    if let Ok(parsed_port) = port_line.trim().parse::<u16>() {
                        debug!("Found SSH port in config: {}", parsed_port);
                        port = parsed_port;
                        break;
                    }
                }
            }
            break; // Stop after reading the first available config file
        }
    }
    
    // Verify the port is reasonable (1-65535)
    if port > 0 {
        Some(port)
    } else {
        warn!("Invalid SSH port detected: {}, defaulting to 22", port);
        Some(22)
    }
}

pub fn collect_system_info() -> Result<SystemInfo> {
    let os_name = System::name().unwrap_or_else(|| "Unknown".to_string());
    let arch = System::cpu_arch().unwrap_or_else(|| "Unknown".to_string());
    let kernel_version = System::kernel_version().unwrap_or_else(|| "Unknown".to_string());
    let os_version = System::os_version().unwrap_or_else(|| "Unknown".to_string());

    // Determine platform based on OS
    let platform = if cfg!(target_os = "linux") {
        "linux".to_string()
    } else if cfg!(target_os = "macos") {
        "darwin".to_string()
    } else if cfg!(target_os = "windows") {
        "windows".to_string()
    } else {
        "unknown".to_string()
    };

    // Try to get distribution info on Linux
    let distribution = {
        #[cfg(target_os = "linux")]
        {
            get_linux_distribution().unwrap_or_else(|| os_name.clone())
        }
        #[cfg(not(target_os = "linux"))]
        {
            os_name.clone()
        }
    };

    let ssh_port = detect_ssh_port();

    Ok(SystemInfo {
        os: os_name,
        arch,
        platform,
        kernel: kernel_version,
        distribution,
        version: os_version,
        ssh_port,
    })
}

pub fn collect_hostname() -> Result<String> {
    hostname::get()
        .map_err(|e| anyhow::anyhow!("Failed to get hostname: {}", e))?
        .to_string_lossy()
        .to_string()
        .pipe(Ok)
}


// Extension trait for pipe operations
trait Pipe<T> {
    fn pipe<U, F>(self, f: F) -> U
    where
        F: FnOnce(Self) -> U,
        Self: Sized;
}

impl<T> Pipe<T> for T {
    fn pipe<U, F>(self, f: F) -> U
    where
        F: FnOnce(Self) -> U,
    {
        f(self)
    }
}
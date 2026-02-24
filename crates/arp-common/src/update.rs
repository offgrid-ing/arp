//! Self-update functionality for ARP binaries from GitHub Releases.
//!
//! Shared by both `arpc` and `arps`. Caller passes their binary name
//! and version; the rest (download, checksum, replace) is identical.

use sha2::{Digest, Sha256};
use std::io::{IsTerminal, Write};

// ANSI style helpers (only used when stderr/stdout is a TTY)
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const CYAN: &str = "\x1b[36m";

const GITHUB_API_URL: &str = "https://api.github.com/repos/offgrid-ing/arp/releases/latest";
const GITHUB_DOWNLOAD_BASE: &str = "https://github.com/offgrid-ing/arp/releases/latest/download";

/// Returns the platform-specific download name (e.g. `arpc-linux-x86_64`).
fn platform_binary(name: &str) -> Result<String, anyhow::Error> {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        "linux" => "linux",
        other => anyhow::bail!("unsupported OS: {other}"),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => anyhow::bail!("unsupported architecture: {other}"),
    };
    Ok(format!("{name}-{os}-{arch}"))
}

/// Builds a reqwest client with User-Agent.
fn http_client(name: &str, version: &str) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .user_agent(format!("{name}/{version}"))
        .build()
}

/// Fetches the latest release tag from GitHub API.
async fn fetch_latest_tag(client: &reqwest::Client) -> Result<String, anyhow::Error> {
    let resp = client
        .get(GITHUB_API_URL)
        .send()
        .await?
        .error_for_status()?;

    let body: serde_json::Value = resp.json().await?;
    let tag = body["tag_name"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing tag_name in GitHub API response"))?
        .to_string();
    Ok(tag)
}

/// Verifies a SHA-256 checksum against expected hex digest.
pub fn verify_checksum(data: &[u8], expected_hex: &str) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let actual = format!("{:x}", hasher.finalize());
    actual == expected_hex
}

/// Placeholder for release signature verification.
/// TODO(C1): Implement Ed25519 signature verification of release artifacts.
#[allow(dead_code)]
fn verify_release_signature(_data: &[u8], _signature: &[u8], _public_key: &[u8; 32]) -> bool {
    false
}

/// Check if an update is available. Prints status and returns.
///
/// # Errors
///
/// Returns an error if the GitHub API request fails.
pub async fn check_for_update(name: &str, version: &str) -> Result<(), anyhow::Error> {
    let client = http_client(name, version)?;
    let current = format!("v{version}");
    let tty = std::io::stdout().is_terminal();

    if tty {
        eprintln!("  {DIM}Checking for updates...{RESET}");
    } else {
        eprintln!("Checking for updates...");
    }

    let latest = fetch_latest_tag(&client).await?;

    if latest == current {
        if tty {
            println!("  {GREEN}\u{2713}{RESET} {name} {BOLD}{current}{RESET} is up to date");
        } else {
            println!("{name} {current} is up to date");
        }
    } else if tty {
        println!(
            "  {CYAN}\u{25cf}{RESET} {name} {DIM}{current}{RESET} \u{2192} {BOLD}{latest}{RESET}"
        );
        println!("    Run {BOLD}{name} update{RESET} to install");
    } else {
        println!("{name} {current} (latest: {latest}) \u{2014} update available");
    }
    Ok(())
}

/// Quietly check if an update is available (for background daemon check).
/// Returns `Ok(Some(latest_tag))` if outdated, `Ok(None)` if up-to-date.
///
/// # Errors
///
/// Returns an error if the GitHub API request fails.
pub async fn check_for_update_quiet(
    name: &str,
    version: &str,
) -> Result<Option<String>, anyhow::Error> {
    let client = http_client(name, version)?;
    let current = format!("v{version}");
    let latest = fetch_latest_tag(&client).await?;
    if latest == current {
        Ok(None)
    } else {
        Ok(Some(latest))
    }
}

/// Self-update: download latest binary, verify checksum, replace current executable.
///
/// # Errors
///
/// Returns an error if the download, checksum verification, or binary replacement fails.
pub async fn perform_update(name: &str, version: &str) -> Result<(), anyhow::Error> {
    let client = http_client(name, version)?;
    let current = format!("v{version}");
    let tty = std::io::stderr().is_terminal();

    if tty {
        eprintln!("  {DIM}Checking for updates...{RESET}");
    } else {
        eprintln!("Checking for updates...");
    }

    let latest = fetch_latest_tag(&client).await?;

    if latest == current {
        if tty {
            println!("  {GREEN}\u{2713}{RESET} {name} {BOLD}{current}{RESET} is up to date");
        } else {
            println!("{name} {current} is up to date");
        }
        return Ok(());
    }

    if tty {
        eprintln!(
            "  {CYAN}\u{25cf}{RESET} {name} {DIM}{current}{RESET} \u{2192} {BOLD}{latest}{RESET}"
        );
    } else {
        println!("{name} {current} \u{2192} {latest}");
    }

    let bin_name = platform_binary(name)?;
    let download_url = format!("{GITHUB_DOWNLOAD_BASE}/{bin_name}");
    let checksum_url = format!("{GITHUB_DOWNLOAD_BASE}/{bin_name}.sha256");

    // Download checksum first (small)
    if tty {
        eprint!("  {DIM}Downloading checksum...{RESET}");
    } else {
        eprint!("Downloading checksum...");
    }
    let checksum_resp = client.get(&checksum_url).send().await?.error_for_status()?;
    let checksum_text = checksum_resp.text().await?;
    let expected_hash = checksum_text
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty checksum file"))?
        .to_lowercase();
    eprintln!(" ok");

    // Download binary
    if tty {
        eprint!("  {DIM}Downloading {bin_name}...{RESET}");
    } else {
        eprint!("Downloading {bin_name}...");
    }
    let bin_resp = client.get(&download_url).send().await?.error_for_status()?;
    let bin_data = bin_resp.bytes().await?;
    eprintln!(" {} bytes", bin_data.len());

    // Verify checksum
    if tty {
        eprint!("  {DIM}Verifying checksum...{RESET}");
    } else {
        eprint!("Verifying checksum...");
    }
    if !verify_checksum(&bin_data, &expected_hash) {
        if tty {
            eprintln!();
            eprintln!("  {RED}\u{2717}{RESET} Checksum verification failed! Aborting update.");
        }
        anyhow::bail!("checksum verification failed! Aborting update.");
    }
    eprintln!(" ok");

    // Write to temp file next to the current binary, then rename
    let current_exe = std::env::current_exe()?;
    let parent = current_exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("cannot determine parent directory of current binary"))?;
    let tmp_path = parent.join(format!(
        ".{name}-update-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    ));

    {
        let mut tmp_file = std::fs::File::create(&tmp_path)?;
        tmp_file.write_all(&bin_data)?;
        tmp_file.flush()?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755))?;
    }

    std::fs::rename(&tmp_path, &current_exe)?;

    if tty {
        println!("  {GREEN}\u{2713}{RESET} Updated {name} to {BOLD}{latest}{RESET}");
    } else {
        println!("Updated {name} to {latest}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_binary_arpc() {
        let name =
            platform_binary("arpc").expect("platform_binary should succeed on supported platforms");
        assert!(
            name.starts_with("arpc-"),
            "should start with 'arpc-': {name}"
        );
        let parts: Vec<&str> = name.split('-').collect();
        assert_eq!(parts.len(), 3, "should have 3 parts: {name}");
    }

    #[test]
    fn platform_binary_arps() {
        let name =
            platform_binary("arps").expect("platform_binary should succeed on supported platforms");
        assert!(
            name.starts_with("arps-"),
            "should start with 'arps-': {name}"
        );
    }

    #[test]
    fn verify_checksum_valid() {
        let data = b"hello world";
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert!(verify_checksum(data, expected));
    }

    #[test]
    fn verify_checksum_invalid() {
        let data = b"hello world";
        let wrong = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(!verify_checksum(data, wrong));
    }

    #[test]
    fn http_client_builds() {
        let client = http_client("arpc", "0.0.0");
        assert!(client.is_ok(), "http_client should build successfully");
    }
}

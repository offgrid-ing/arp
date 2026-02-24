//! Self-update functionality for arpc binary from GitHub Releases.

use sha2::{Digest, Sha256};
use std::io::Write;

const GITHUB_API_URL: &str = "https://api.github.com/repos/offgrid-ing/arp/releases/latest";
const GITHUB_DOWNLOAD_BASE: &str = "https://github.com/offgrid-ing/arp/releases/latest/download";

/// Returns the current version string prefixed with "v".
fn current_version() -> String {
    format!("v{}", env!("CARGO_PKG_VERSION"))
}

/// Returns the platform-specific binary name (e.g. `arpc-linux-x86_64`).
fn binary_name() -> Result<String, anyhow::Error> {
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
    Ok(format!("arpc-{os}-{arch}"))
}

/// Builds a reqwest client with the required User-Agent header.
fn http_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .user_agent(format!("arpc/{}", env!("CARGO_PKG_VERSION")))
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
fn verify_checksum(data: &[u8], expected_hex: &str) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let actual = format!("{:x}", hasher.finalize());
    actual == expected_hex
}

/// Placeholder for release signature verification.
/// TODO(C1): Implement Ed25519 signature verification of release artifacts.
/// This requires:
/// 1. A release signing keypair (generated offline, public key embedded here)
/// 2. CI pipeline to sign release artifacts
/// 3. Verification of detached .sig files before applying updates
#[allow(dead_code)]
fn verify_release_signature(_data: &[u8], _signature: &[u8], _public_key: &[u8; 32]) -> bool {
    // Placeholder — always returns false until signing infrastructure is in place
    tracing::warn!("release signature verification not yet implemented (C1)");
    false
}
/// Check if an update is available. Prints status and returns.
///
/// # Errors
///
/// Returns an error if the GitHub API request fails.
pub async fn check_for_update() -> Result<(), anyhow::Error> {
    let client = http_client()?;
    let current = current_version();

    eprintln!("Checking for updates...");

    let latest = fetch_latest_tag(&client).await?;

    if latest == current {
        println!("arpc {current} is up to date");
    } else {
        println!("arpc {current} (latest: {latest}) — update available");
    }
    Ok(())
}

/// Quietly check if an update is available (for background daemon check).
/// Returns `Ok(Some(latest_tag))` if outdated, `Ok(None)` if up-to-date.
///
/// # Errors
///
/// Returns an error if the GitHub API request fails.
pub async fn check_for_update_quiet() -> Result<Option<String>, anyhow::Error> {
    let client = http_client()?;
    let current = current_version();
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
pub async fn perform_update() -> Result<(), anyhow::Error> {
    let client = http_client()?;
    let current = current_version();

    eprintln!("Checking for updates...");

    let latest = fetch_latest_tag(&client).await?;

    if latest == current {
        println!("arpc {current} is up to date");
        return Ok(());
    }

    println!("arpc {current} → {latest}");

    let bin_name = binary_name()?;
    let download_url = format!("{GITHUB_DOWNLOAD_BASE}/{bin_name}");
    let checksum_url = format!("{GITHUB_DOWNLOAD_BASE}/{bin_name}.sha256");

    // Download checksum first (small)
    eprint!("Downloading checksum...");
    let checksum_resp = client.get(&checksum_url).send().await?.error_for_status()?;
    let checksum_text = checksum_resp.text().await?;
    // Checksum file format: "<hex>  <filename>" or just "<hex>"
    let expected_hash = checksum_text
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty checksum file"))?
        .to_lowercase();
    eprintln!(" ok");

    // Download binary
    eprint!("Downloading {bin_name}...");
    let bin_resp = client.get(&download_url).send().await?.error_for_status()?;
    let bin_data = bin_resp.bytes().await?;
    eprintln!(" {} bytes", bin_data.len());

    // Verify checksum
    eprint!("Verifying checksum...");
    if !verify_checksum(&bin_data, &expected_hash) {
        anyhow::bail!("checksum verification failed! Aborting update.");
    }
    eprintln!(" ok");

    // Write to temp file next to the current binary, then rename
    let current_exe = std::env::current_exe()?;
    let parent = current_exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("cannot determine parent directory of current binary"))?;
    // Use a unique temp file name to avoid race conditions with multiple processes
    let tmp_path = parent.join(format!(
        ".arpc-update-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    ));

    // Write temp file
    {
        let mut tmp_file = std::fs::File::create(&tmp_path)?;
        tmp_file.write_all(&bin_data)?;
        tmp_file.flush()?;
    }

    // Set executable permissions on unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755))?;
    }

    // Atomic-ish replace: rename over current binary
    std::fs::rename(&tmp_path, &current_exe)?;

    println!("Updated arpc to {latest}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_version_has_v_prefix() {
        let version = current_version();
        assert!(
            version.starts_with('v'),
            "version should start with 'v': {version}"
        );
    }

    #[test]
    fn test_binary_name_format() {
        let name = binary_name().expect("binary_name should succeed on supported platforms");
        assert!(
            name.starts_with("arpc-"),
            "binary name should start with 'arpc-': {name}"
        );
        // Should contain os and arch
        let parts: Vec<&str> = name.split('-').collect();
        assert_eq!(parts.len(), 3, "binary name should have 3 parts: {name}");
    }

    #[test]
    fn test_verify_checksum_valid() {
        let data = b"hello world";
        // SHA-256 of "hello world"
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert!(verify_checksum(data, expected));
    }

    #[test]
    fn test_verify_checksum_invalid() {
        let data = b"hello world";
        let wrong = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(!verify_checksum(data, wrong));
    }

    #[test]
    fn test_http_client_builds() {
        let client = http_client();
        assert!(client.is_ok(), "http_client should build successfully");
    }
}

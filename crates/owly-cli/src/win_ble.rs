//! Windows BLE AirDrop wake advertisement helper.
//!
//! Invokes `airdrop-beacon.ps1` using Windows PowerShell 5.1
//! (`powershell.exe`) so nearby Apple devices turn AWDL on and open their
//! AirDrop port. Stops the PowerShell process cleanly on `Drop`.

use std::io;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

pub struct WinBleAdvert {
    child: Child,
}

impl WinBleAdvert {
    pub async fn start() -> io::Result<Self> {
        let script = find_beacon_script()?;
        let mut child = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(&script)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;

        if let Some(stdout) = child.stdout.take() {
            let mut lines = BufReader::new(stdout).lines();
            match tokio::time::timeout(Duration::from_secs(6), lines.next_line()).await {
                Ok(Ok(Some(line))) if line.trim() == "advertising" => {
                    tracing::info!("Windows BLE AirDrop beacon started ({})", script.display());
                }
                Ok(Ok(Some(line))) => {
                    let _ = child.start_kill();
                    return Err(io::Error::other(format!("BLE beacon: {line}")));
                }
                Ok(Ok(None)) => {
                    let _ = child.start_kill();
                    return Err(io::Error::other("BLE beacon exited before advertising"));
                }
                Ok(Err(e)) => {
                    let _ = child.start_kill();
                    return Err(e);
                }
                Err(_) => {
                    tracing::warn!("BLE beacon did not report ready within 6s; continuing");
                }
            }
        }

        Ok(Self { child })
    }
}

impl Drop for WinBleAdvert {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

fn find_beacon_script() -> io::Result<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = std::env::var_os("OWLY_BEACON_SCRIPT") {
        candidates.push(PathBuf::from(p));
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        candidates.push(dir.join("airdrop-beacon.ps1"));
        candidates.push(dir.join("scripts").join("airdrop-beacon.ps1"));
    }
    candidates.push(PathBuf::from(r"scripts\airdrop-beacon.ps1"));
    candidates.push(PathBuf::from(
        r"..\nekodrop-0.1.21-windows-x64\scripts\airdrop-beacon.ps1",
    ));
    candidates.push(PathBuf::from(
        r"C:\Users\20662\Desktop\MTKAWDL\nekodrop-0.1.21-windows-x64\scripts\airdrop-beacon.ps1",
    ));

    for path in candidates {
        if path.is_file() {
            return Ok(path);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "airdrop-beacon.ps1 not found (set OWLY_BEACON_SCRIPT or place in scripts\\airdrop-beacon.ps1)",
    ))
}

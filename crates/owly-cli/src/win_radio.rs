//! Windows `owly radio up` and in-process `mtkradio.exe` Named Pipe bridge.

use std::io;
use std::net::Ipv6Addr;
use std::process::ExitCode;
use std::time::Duration;

use owly_awdl::{Channel, Config, MacAddr, PeerInfo, Presence, RadioConstraints, TxRate};
use owly_radio::native::Native;
use tokio::sync::watch;

/// Default locally-administered AWDL MAC used with `mtkradio`.
pub const DEFAULT_AWDL_MAC: MacAddr = MacAddr([0x02, 0x79, 0x22, 0x55, 0x6d, 0x0d]);

/// Starts `owly-awdl` over `mtkradio.exe`'s Named Pipe with our proven MT7922
/// VHT80 / ADDBA / A-MSDU configuration, returning the running node, peer
/// watcher, and the Wintun interface's EUI-64 IPv6 link-local address.
pub fn start_mtkradio(
    pipe: &str,
    iface: &str,
    ch_num: u32,
    host_name: &str,
) -> io::Result<(Native, watch::Receiver<Vec<PeerInfo>>, Ipv6Addr)> {
    let freq_mhz = if ch_num <= 13 {
        2407 + ch_num * 5
    } else {
        5000 + ch_num * 5
    };
    let channel = Channel::from_freq_mhz(freq_mhz).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("channel {ch_num} is not a valid AWDL channel (use 6, 44, or 149)"),
        )
    })?;

    let mut cfg = Config::new(
        DEFAULT_AWDL_MAC,
        host_name,
        RadioConstraints {
            channel,
            presence: Presence::Fixed,
        },
    );
    let rate = select_tx_rate(ch_num);
    let amsdu = std::env::var("OWLY_NO_AMSDU")
        .map(|v| v.trim() == "0")
        .unwrap_or(false);
    let no_ack = std::env::var("OWLY_NO_ACK")
        .map(|v| v.trim() == "1")
        .unwrap_or(false);
    let continuous_tx = std::env::var("OWLY_CONTINUOUS_TX")
        .map(|v| v.trim() == "1")
        .unwrap_or(false);
    cfg.rate = rate;
    cfg.no_ack = no_ack;
    cfg.accept_addba = true;
    cfg.initiate_addba = true;
    cfg.amsdu = amsdu;
    cfg.continuous_tx = continuous_tx;
    // Keep 2-subframe A-MSDUs safely below MT7922/VHT's 3,895-byte Max MPDU limit.
    cfg.max_frame = 3200;

    let link_local = cfg.addr.link_local();
    let (peers_tx, peers_rx) = watch::channel(Vec::new());
    let native = Native::start_pipe(pipe, iface, cfg, peers_tx)?;
    eprintln!(
        "[owly-win] {iface} up (ifindex={}, ip={link_local}, pipe={pipe}, ch={ch_num}, rate={rate}, no_ack={no_ack}, RX+TX-ADDBA, amsdu={amsdu}, cont_tx={continuous_tx})",
        native.index
    );
    Ok((native, peers_rx, link_local))
}

fn select_tx_rate(ch_num: u32) -> TxRate {
    if ch_num <= 14 {
        return TxRate::Ht { mcs: 7, sgi: true };
    }
    if let Ok(val) = std::env::var("OWLY_VHT_MCS") {
        let v = val.trim();
        if v.eq_ignore_ascii_case("ht7") {
            return TxRate::Ht { mcs: 7, sgi: true };
        }
        if let Ok(mcs) = v.parse::<u8>() {
            return TxRate::Vht {
                mcs: mcs.min(9),
                nss: 2,
                bw_mhz: 80,
                sgi: true,
            };
        }
    }
    TxRate::Vht {
        mcs: 7,
        nss: 2,
        bw_mhz: 80,
        sgi: true,
    }
}

/// `owly radio up` on Windows: brings up Wintun `awdl0` connected to
/// `mtkradio.exe` and holds it until Ctrl-C (or `duration` seconds).
pub async fn up(pipe: &str, iface: &str, channel: u32, duration: u32) -> Result<ExitCode, String> {
    let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "owly-MT7922".into());
    let (native, mut peers_rx, _addr) =
        start_mtkradio(pipe, iface, channel, &host).map_err(|e| e.to_string())?;
    let mut failed = native.failed();

    let deadline = if duration > 0 {
        Some(tokio::time::Instant::now() + Duration::from_secs(duration as u64))
    } else {
        None
    };

    let code = loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("[owly-win] stopping on Ctrl-C...");
                break ExitCode::SUCCESS;
            }
            _ = async {
                if let Some(d) = deadline {
                    tokio::time::sleep_until(d).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                eprintln!("[owly-win] duration elapsed, stopping...");
                break ExitCode::SUCCESS;
            }
            changed = failed.changed() => {
                if changed.is_ok() && let Some(err) = failed.borrow().as_ref() {
                    eprintln!("[owly-win] AWDL node failed: {err}");
                    break ExitCode::from(2);
                }
            }
            changed = peers_rx.changed() => {
                if changed.is_ok() {
                    let peers = peers_rx.borrow_and_update();
                    eprintln!("[owly-win] peers ({}):", peers.len());
                    for p in peers.iter() {
                        eprintln!("  - {} name={:?} rssi={:?}", p.mac, p.name, p.rssi);
                    }
                }
            }
        }
    };

    native.stop();
    Ok(code)
}

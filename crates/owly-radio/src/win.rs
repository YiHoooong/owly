//! owly-awdl on Windows: its [`driver`] over a user-space radio daemon's
//! Named Pipe (`\\.\pipe\winawdl-radio`, using the `radio_link.h` framing)
//! and a Layer-3 Wintun adapter (`awdl0`).
//!
//! Its [`Air`] is [`PipeAir`] (or [`DirectMtkAir`]), talking to `mtkradio.exe`
//! over a duplex overlapped Windows Named Pipe or directly via `mtkradio_core.dll`.
//! Its [`Netif`] is [`WintunNetif`], a Wintun adapter configured with MTU 1500
//! (configurable via `OWLY_MTU`), optional Software GRO TCP coalescing, and
//! the AWDL MAC's EUI-64 IPv6 link-local address without DAD (NET-1).

use std::collections::VecDeque;
use std::ffi::{CStr, CString, c_char, c_void};
use std::io;
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use owly_awdl::driver::{self, Air, Netif, Received, Running};
use owly_awdl::frame::Frame;
use owly_awdl::{Config, Ipv6Packet, PeerInfo, TxRate};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tokio::sync::{mpsc, watch};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_NO_MORE_ITEMS, ERROR_OBJECT_ALREADY_EXISTS, ERROR_PIPE_BUSY, FreeLibrary,
    HANDLE, HMODULE, NO_ERROR, WAIT_OBJECT_0,
};
use windows_sys::Win32::Media::{timeBeginPeriod, timeEndPeriod};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex, CreateUnicastIpAddressEntry,
    DeleteUnicastIpAddressEntry, FreeMibTable, GetIpInterfaceEntry, GetUnicastIpAddressTable,
    InitializeUnicastIpAddressEntry, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
    MIB_UNICASTIPADDRESS_TABLE, SetIpInterfaceEntry,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET6, IpDadStatePreferred, IpPrefixOriginManual, IpSuffixOriginManual,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_REMOVED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenPrivileges,
};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, INFINITE, OpenProcessToken, SetEvent, WaitForMultipleObjects,
};

use crate::radiotap;

/// Default Named Pipe served by `mtkradio.exe` (`RADIO_LINK_PIPE_NAME`).
pub const DEFAULT_PIPE: &str = r"\\.\pipe\winawdl-radio";

/// Default `awdl0` MTU (overrideable via `OWLY_MTU` env var).
pub const TAP_MTU: u32 = 1500;
/// Minimum IPv6 MTU (RFC 8200).
const MIN_IPV6_MTU: u32 = 1280;
/// Maximum MTU supported over MT7922 4 KiB DMA pages.
const MAX_AWDL_MTU: u32 = 3800;

/// Returns the configured `awdl0` MTU from `OWLY_MTU`, falling back to `default`
/// (typically [`TAP_MTU`] = 1500), clamped to `[1280, 3800]`.
pub fn configured_mtu_or(default: u32) -> u32 {
    let fallback = default.clamp(MIN_IPV6_MTU, MAX_AWDL_MTU);
    let Ok(raw) = std::env::var("OWLY_MTU") else {
        return fallback;
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return fallback;
    }
    match trimmed.parse::<u32>() {
        Ok(val) => {
            let clamped = val.clamp(MIN_IPV6_MTU, MAX_AWDL_MTU);
            if clamped != val {
                tracing::warn!(
                    "OWLY_MTU={val} out of range [{MIN_IPV6_MTU}..={MAX_AWDL_MTU}], clamped to {clamped}"
                );
            }
            clamped
        }
        Err(_) => {
            tracing::warn!("invalid OWLY_MTU={raw:?}, using {fallback}");
            fallback
        }
    }
}

/// Returns the configured `awdl0` MTU from `OWLY_MTU` (default [`TAP_MTU`] = 1500).
pub fn configured_mtu() -> u32 {
    configured_mtu_or(TAP_MTU)
}

/// Returns whether Wintun Software GRO (TCP receive segment coalescing) is enabled.
/// Enabled by default; set `OWLY_NO_GRO=1` to disable for A/B benchmarking.
pub fn gro_enabled() -> bool {
    !std::env::var("OWLY_NO_GRO")
        .map(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

const RADIO_LINK_HELLO: u16 = 1;
const RADIO_LINK_RX: u16 = 2;
const RADIO_LINK_TX: u16 = 3;
const RADIO_LINK_SET_BSSID_FILTER: u16 = 5;
const RADIO_LINK_SET_ADDRESS: u16 = 6;
const AWDL_BSSID: [u8; 6] = [0x00, 0x25, 0x00, 0xff, 0x94, 0x73];

/// Size of `PipeAir`'s internal read buffer so one read pulls many frames.
const PIPE_RX_BUF: usize = 256 * 1024;
/// Maximum `radio_link` payload accepted from `mtkradio`.
const PIPE_MAX_BODY: usize = 16 * 1024;
/// Bounded TX queue capacity between `Air::send` and the async pipe writer task.
const TX_QUEUE_CAP: usize = 1024;
/// Maximum bytes combined into one batched Named Pipe `WriteFile` call.
const TX_BATCH_MAX: usize = 128 * 1024;
/// Wintun ring buffer capacity (8 MiB).
const WINTUN_RING_CAPACITY: u32 = 0x80_0000;
/// Bounded RX queue capacity between `wintun-rx` thread and `owly-awdl`.
const WINTUN_RX_QUEUE_CAP: usize = 4096;

/// RAII guard that requests 1 ms Windows system timer resolution
/// (`timeBeginPeriod(1)`) so `owly-awdl`'s timers don't suffer 15.6 ms jitter.
struct HighResTimer(u32);

impl HighResTimer {
    fn new(ms: u32) -> Self {
        #[allow(unsafe_code)]
        // SAFETY: `timeBeginPeriod` takes a plain integer millisecond period.
        unsafe {
            timeBeginPeriod(ms);
        }
        Self(ms)
    }
}

impl Drop for HighResTimer {
    fn drop(&mut self) {
        #[allow(unsafe_code)]
        // SAFETY: Matches the `timeBeginPeriod(self.0)` call in `Self::new`.
        unsafe {
            timeEndPeriod(self.0);
        }
    }
}

/// A running node on Windows.
pub struct Native {
    running: Running,
    /// `awdl0`'s interface index (IPv6 scope ID).
    pub index: u32,
    _timer: HighResTimer,
}

impl Native {
    /// Connects to a user-space radio daemon (`mtkradio.exe`) over a Windows
    /// Named Pipe using the `radio_link` framing protocol, creates a Wintun
    /// adapter named `tap`, and starts `owly-awdl` on it.
    pub fn start_socket(
        pipe_path: &str,
        tap: &str,
        cfg: Config,
        peers: watch::Sender<Vec<PeerInfo>>,
    ) -> io::Result<Native> {
        Self::start_pipe(pipe_path, tap, cfg, peers)
    }

    /// Windows-named alias for [`Self::start_socket`].
    pub fn start_pipe(
        pipe_path: &str,
        tap: &str,
        cfg: Config,
        peers: watch::Sender<Vec<PeerInfo>>,
    ) -> io::Result<Native> {
        let timer = HighResTimer::new(1);
        let link_local = cfg.addr.link_local();
        let mtu = configured_mtu_or(u32::from(cfg.mtu));
        let wintun = WintunAdapter::create(tap, link_local, mtu)?;
        let index = wintun.index;
        let mac = cfg.addr.0;
        let ch = cfg.radio.channel.0;
        let pipe_path = pipe_path.to_string();

        let running = if pipe_path == "direct" || pipe_path.starts_with("direct:") {
            let fw_dir = pipe_path
                .strip_prefix("direct:")
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .or_else(|| std::env::var("OWLY_MTK_FW_DIR").ok())
                .unwrap_or_else(|| {
                    r"C:\Users\20662\Desktop\MTKAWDL\nekodrop\mtkradio\build\firmware".into()
                });
            let width_mhz: u32 = if ch <= 14 { 20 } else { 80 };
            driver::spawn(
                cfg,
                move || {
                    let air = DirectMtkAir::open(&fw_dir, ch, width_mhz, mac)?;
                    let netif = WintunNetif::start(wintun)?;
                    drop_process_privileges();
                    Ok((air, netif))
                },
                peers,
            )?
        } else {
            driver::spawn(
                cfg,
                move || {
                    let air = PipeAir::connect(&pipe_path, mac)?;
                    let netif = WintunNetif::start(wintun)?;
                    Ok((air, netif))
                },
                peers,
            )?
        };
        Ok(Native {
            running,
            index,
            _timer: timer,
        })
    }

    /// Why the node stopped by itself, once it has.
    pub fn failed(&self) -> watch::Receiver<Option<String>> {
        self.running.failed()
    }

    /// Stops the node and closes the Wintun adapter.
    pub fn stop(self) {
        self.running.stop();
    }
}

/// Looks up a Windows network interface by alias (such as `"awdl0"`) and
/// returns its interface index (IPv6 scope ID) and first IPv6 link-local
/// address.
pub fn lookup_interface(name: &str) -> io::Result<(u32, Ipv6Addr)> {
    let wide = to_wide(name);
    let mut luid: NET_LUID_LH = NET_LUID_LH { Value: 0 };
    #[allow(unsafe_code)]
    // SAFETY: `wide` is NUL-terminated UTF-16 and `luid` is valid writable memory.
    let err = unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut luid) };
    if err != NO_ERROR {
        return Err(io::Error::from_raw_os_error(err as i32));
    }

    let mut index: u32 = 0;
    #[allow(unsafe_code)]
    // SAFETY: `luid` and `index` are valid pointers.
    let err = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
    if err != NO_ERROR {
        return Err(io::Error::from_raw_os_error(err as i32));
    }

    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = ptr::null_mut();
    #[allow(unsafe_code)]
    // SAFETY: `table` receives an allocated MIB table freed with `FreeMibTable`.
    let err = unsafe { GetUnicastIpAddressTable(AF_INET6, &mut table) };
    if err != NO_ERROR {
        return Err(io::Error::from_raw_os_error(err as i32));
    }

    let mut found = None;
    #[allow(unsafe_code)]
    // SAFETY: `table` is non-null on `NO_ERROR` and holds `NumEntries` rows.
    unsafe {
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        let target_luid = luid.Value;
        for row in rows {
            if row.InterfaceLuid.Value == target_luid {
                let bytes = row.Address.Ipv6.sin6_addr.u.Byte;
                let ip = Ipv6Addr::from(bytes);
                if ip.segments()[0] & 0xffc0 == 0xfe80 {
                    found = Some(ip);
                    break;
                }
            }
        }
        FreeMibTable(table.cast());
    }

    let addr = found.ok_or_else(|| {
        io::Error::other(format!("{name} has no IPv6 link-local address"))
    })?;
    Ok((index, addr))
}

/// Cancel-safe Windows Named Pipe `Air` implementation for `mtkradio.exe`.
struct PipeAir {
    rx: ReadHalf<NamedPipeClient>,
    tx: mpsc::Sender<Vec<u8>>,
    rx_buf: Vec<u8>,
    rx_start: usize,
    rx_end: usize,
}

impl PipeAir {
    fn connect(pipe_path: &str, own_mac: [u8; 6]) -> io::Result<Self> {
        let client = open_pipe_with_retry(pipe_path)?;
        let (rx, mut tx_half) = tokio::io::split(client);
        let (tx, mut tx_rx) = mpsc::channel::<Vec<u8>>(TX_QUEUE_CAP);

        // Build initial control frames (RADIO_LINK_SET_ADDRESS + RADIO_LINK_SET_BSSID_FILTER).
        let mut init = Vec::with_capacity(28);
        init.extend_from_slice(&RADIO_LINK_SET_ADDRESS.to_le_bytes());
        init.extend_from_slice(&0u16.to_le_bytes());
        init.extend_from_slice(&6u32.to_le_bytes());
        init.extend_from_slice(&own_mac);

        init.extend_from_slice(&RADIO_LINK_SET_BSSID_FILTER.to_le_bytes());
        init.extend_from_slice(&0u16.to_le_bytes());
        init.extend_from_slice(&6u32.to_le_bytes());
        init.extend_from_slice(&AWDL_BSSID);

        tokio::spawn(async move {
            if let Err(e) = tx_half.write_all(&init).await {
                tracing::warn!("mtkradio pipe init write failed: {e}");
                return;
            }
            let mut batch = Vec::with_capacity(TX_BATCH_MAX);
            while let Some(pkt) = tx_rx.recv().await {
                batch.clear();
                batch.extend_from_slice(&pkt);
                while batch.len() < TX_BATCH_MAX {
                    match tx_rx.try_recv() {
                        Ok(more) => batch.extend_from_slice(&more),
                        Err(_) => break,
                    }
                }
                if let Err(e) = tx_half.write_all(&batch).await {
                    tracing::debug!("mtkradio pipe write failed: {e}");
                    break;
                }
            }
        });

        Ok(Self {
            rx,
            tx,
            rx_buf: vec![0u8; PIPE_RX_BUF],
            rx_start: 0,
            rx_end: 0,
        })
    }
}

fn open_pipe_with_retry(pipe_path: &str) -> io::Result<NamedPipeClient> {
    for attempt in 0..40 {
        match ClientOptions::new().open(pipe_path) {
            Ok(client) => return Ok(client),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && attempt < 39 => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("failed to open radio pipe {pipe_path}: {e} (is mtkradio.exe running as Administrator?)"),
                ));
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("radio pipe {pipe_path} stayed busy"),
    ))
}

/// Appends the radiotap TX header for `rate`/`no_ack` into `out` without allocating.
/// Matches [`radiotap::tx_header`] byte-for-byte.
fn write_tx_radiotap(out: &mut Vec<u8>, rate: TxRate, no_ack: bool) {
    match rate {
        TxRate::Legacy(r) => {
            if no_ack {
                out.extend_from_slice(&[0, 0, 12, 0, 0x04, 0x80, 0, 0, r, 0, 0x08, 0]);
            } else {
                out.extend_from_slice(&[0, 0, 9, 0, 0x04, 0, 0, 0, r]);
            }
        }
        TxRate::Ht { mcs, sgi } => {
            let flags = if sgi { 0x04 } else { 0 };
            if no_ack {
                out.extend_from_slice(&[0, 0, 13, 0, 0, 0x80, 0x08, 0, 0x08, 0, 0x07, flags, mcs]);
            } else {
                out.extend_from_slice(&[0, 0, 11, 0, 0, 0, 0x08, 0, 0x07, flags, mcs]);
            }
        }
        TxRate::Vht {
            mcs,
            nss,
            bw_mhz,
            sgi,
        } => {
            let flags = if sgi { 0x04 } else { 0x00 };
            let bw = match bw_mhz {
                80 => 4,
                40 => 1,
                _ => 0,
            };
            let mcs_nss = ((mcs & 0x0f) << 4) | (nss.clamp(1, 4) & 0x0f);
            if no_ack {
                out.extend_from_slice(&[
                    0, 0, 22, 0, 0, 0x80, 0x20, 0, 0x08, 0, 0x44, 0x00, flags, bw, mcs_nss, 0, 0,
                    0, 0x01, 0, 0, 0,
                ]);
            } else {
                out.extend_from_slice(&[
                    0, 0, 20, 0, 0, 0, 0x20, 0, 0x44, 0x00, flags, bw, mcs_nss, 0, 0, 0, 0x01, 0,
                    0, 0,
                ]);
            }
        }
    }
}

impl PipeAir {
    fn pop_buffered(&mut self) -> io::Result<Option<Received>> {
        loop {
            let avail = self.rx_end - self.rx_start;
            if avail < 8 {
                return Ok(None);
            }
            let hdr = &self.rx_buf[self.rx_start..self.rx_start + 8];
            let msg_type = u16::from_le_bytes([hdr[0], hdr[1]]);
            let body_len = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
            if body_len > PIPE_MAX_BODY {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "oversized radio_link frame",
                ));
            }
            let frame_len = 8 + body_len;
            if avail < frame_len {
                return Ok(None);
            }
            let body_start = self.rx_start + 8;
            let body_end = self.rx_start + frame_len;
            self.rx_start = body_end;
            if self.rx_start == self.rx_end {
                self.rx_start = 0;
                self.rx_end = 0;
            }
            if msg_type == RADIO_LINK_RX {
                if let Some(rx) = radiotap::parse(&self.rx_buf[body_start..body_end]) {
                    return Ok(Some(Received {
                        bytes: rx.frame.to_vec(),
                        rssi: rx.rssi,
                    }));
                }
            } else if msg_type == RADIO_LINK_HELLO && body_len >= 8 {
                let b = &self.rx_buf[body_start..body_end];
                let ver = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
                tracing::info!(
                    "mtkradio pipe hello: version={} ch={} width={}MHz",
                    ver,
                    b[4],
                    b[5]
                );
            }
        }
    }
}

impl Air for PipeAir {
    async fn recv(&mut self) -> io::Result<Received> {
        loop {
            if let Some(rx) = self.pop_buffered()? {
                return Ok(rx);
            }

            if self.rx_start > 0 && self.rx_buf.len() - self.rx_end < PIPE_MAX_BODY + 8 {
                self.rx_buf.copy_within(self.rx_start..self.rx_end, 0);
                self.rx_end -= self.rx_start;
                self.rx_start = 0;
            }

            let n = self.rx.read(&mut self.rx_buf[self.rx_end..]).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "mtkradio pipe closed",
                ));
            }
            self.rx_end += n;
        }
    }

    fn try_recv(&mut self) -> Option<Received> {
        self.pop_buffered().ok().flatten()
    }

    fn send(&mut self, frame: Frame) -> Result<(), Frame> {
        let mut buf = Vec::with_capacity(8 + 16 + frame.bytes.len());
        buf.extend_from_slice(&RADIO_LINK_TX.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        write_tx_radiotap(&mut buf, frame.rate, frame.no_ack);
        buf.extend_from_slice(&frame.bytes);
        let payload_len = (buf.len() - 8) as u32;
        buf[4..8].copy_from_slice(&payload_len.to_le_bytes());

        match self.tx.try_send(buf) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(frame),
            Err(mpsc::error::TrySendError::Closed(_)) => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Direct in-process MT7922 DMA Air (mtkradio_core.dll, zero Named Pipe IPC)
// ---------------------------------------------------------------------------

type MtkRxCallback = unsafe extern "C" fn(*const u8, usize, i8, *mut c_void);
type MtkLogCallback = unsafe extern "C" fn(*const c_char, *mut c_void);

type MtkOpenFn = unsafe extern "C" fn(
    *const c_char,
    u8,
    u32,
    *const u8,
    *const u8,
    i32,
    Option<MtkLogCallback>,
    *mut c_void,
    *mut c_char,
    usize,
) -> *mut c_void;
type MtkTransmitFn = unsafe extern "C" fn(
    *mut c_void,
    *const u8,
    usize,
    u8,
    u8,
    u8,
    u8,
    u8,
    u8,
    u8,
) -> i32;
type MtkKickTxFn = unsafe extern "C" fn(*mut c_void);
type MtkPollFn = unsafe extern "C" fn(*mut c_void, Option<MtkRxCallback>, *mut c_void) -> usize;
type MtkCloseFn = unsafe extern "C" fn(*mut c_void);

struct MtkCoreDll {
    module: HMODULE,
    open: MtkOpenFn,
    transmit: MtkTransmitFn,
    kick_tx: MtkKickTxFn,
    poll: MtkPollFn,
    close: MtkCloseFn,
}

#[allow(unsafe_code)]
// SAFETY: `MtkCoreDll` holds a loaded DLL handle and immutable function pointers
// valid until `FreeLibrary` runs when dropped.
unsafe impl Send for MtkCoreDll {}
#[allow(unsafe_code)]
unsafe impl Sync for MtkCoreDll {}

impl Drop for MtkCoreDll {
    fn drop(&mut self) {
        if !self.module.is_null() {
            #[allow(unsafe_code)]
            unsafe {
                FreeLibrary(self.module);
            }
        }
    }
}

impl MtkCoreDll {
    fn load() -> io::Result<Arc<Self>> {
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Some(p) = std::env::var_os("OWLY_MTKRADIO_DLL") {
            candidates.push(PathBuf::from(p));
        }
        if let Ok(exe) = std::env::current_exe()
            && let Some(dir) = exe.parent()
        {
            candidates.push(dir.join("mtkradio_core.dll"));
        }
        candidates.push(PathBuf::from("mtkradio_core.dll"));
        candidates.push(PathBuf::from(
            r"..\nekodrop\mtkradio\build\mtkradio_core.dll",
        ));
        candidates.push(PathBuf::from(
            r"C:\Users\20662\Desktop\MTKAWDL\nekodrop\mtkradio\build\mtkradio_core.dll",
        ));

        let mut module: HMODULE = ptr::null_mut();
        for path in &candidates {
            if path.is_absolute() && !path.exists() {
                continue;
            }
            let wide = to_wide_os(path);
            #[allow(unsafe_code)]
            let h = unsafe { LoadLibraryW(wide.as_ptr()) };
            if !h.is_null() {
                tracing::info!("loaded mtkradio_core.dll from {}", path.display());
                module = h;
                break;
            }
        }
        if module.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "could not load mtkradio_core.dll (set OWLY_MTKRADIO_DLL or place next to owly.exe)",
            ));
        }

        macro_rules! load_sym {
            ($name:literal, $ty:ty) => {{
                #[allow(unsafe_code)]
                let proc = unsafe { GetProcAddress(module, concat!($name, "\0").as_ptr()) };
                let Some(f) = proc else {
                    #[allow(unsafe_code)]
                    unsafe {
                        FreeLibrary(module);
                    }
                    return Err(io::Error::other(concat!(
                        "missing symbol in mtkradio_core.dll: ",
                        $name
                    )));
                };
                #[allow(unsafe_code)]
                unsafe {
                    std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(f)
                }
            }};
        }

        Ok(Arc::new(Self {
            module,
            open: load_sym!("mtk_open", MtkOpenFn),
            transmit: load_sym!("mtk_transmit", MtkTransmitFn),
            kick_tx: load_sym!("mtk_kick_tx", MtkKickTxFn),
            poll: load_sym!("mtk_poll", MtkPollFn),
            close: load_sym!("mtk_close", MtkCloseFn),
        }))
    }
}

#[allow(unsafe_code)]
unsafe extern "C" fn direct_mtk_log_cb(msg: *const c_char, _ctx: *mut c_void) {
    if msg.is_null() {
        return;
    }
    let s = unsafe { CStr::from_ptr(msg) }.to_string_lossy();
    tracing::info!("[mtkradio-direct] {s}");
}

/// Maximum RX frames buffered inside `RxBridge` if `owly-awdl` lags while
/// `mtk-dma` polls `mtk_poll` to reclaim `TX_FREE` tokens.
const MTK_RX_OVERFLOW_CAP: usize = 8192;
/// Maximum 802.11 RX frame length accepted from `mtkradio_core.dll` (16 KiB,
/// comfortably above MT7922's 12,288 B `MAX_RX_LEN` for multi-subframe RX A-MSDUs).
const MTK_MAX_RX_FRAME: usize = 16 * 1024;
/// Immediate `mtk_poll` + retry spins when `mtk_transmit` returns 0 (all 64
/// hardware `TX_FREE` tokens in flight or 256-slot DMA ring full).
const TX_BACKPRESSURE_INLINE_RETRIES: usize = 8;
/// Upper bound on holding a single pending TX frame (exceeds mtkradio's 1000 ms
/// `TX_FREE` token reaper so an invalid/oversized frame can never permanently wedge TX).
const TX_BACKPRESSURE_MAX_WAIT: Duration = Duration::from_millis(1200);

/// Bridges `mtk_poll` RX callbacks into `tokio::sync::mpsc::Sender<Received>`
/// with an internal `VecDeque` overflow buffer so RX frames are never dropped
/// while `mtk-dma` polls `mtk_poll` during 64-token TX backpressure.
struct RxBridge {
    tx: mpsc::Sender<Received>,
    overflow: VecDeque<Received>,
    dropped: u64,
}

impl RxBridge {
    fn new(tx: mpsc::Sender<Received>) -> Self {
        Self {
            tx,
            overflow: VecDeque::with_capacity(256),
            dropped: 0,
        }
    }

    fn drain(&mut self) {
        while let Some(front) = self.overflow.pop_front() {
            match self.tx.try_send(front) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(pkt)) => {
                    self.overflow.push_front(pkt);
                    break;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.overflow.clear();
                    break;
                }
            }
        }
    }

    fn push(&mut self, pkt: Received) {
        self.drain();
        if self.overflow.is_empty() {
            match self.tx.try_send(pkt) {
                Ok(()) => return,
                Err(mpsc::error::TrySendError::Full(pkt)) => {
                    self.overflow.push_back(pkt);
                    return;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => return,
            }
        }
        if self.overflow.len() < MTK_RX_OVERFLOW_CAP {
            self.overflow.push_back(pkt);
        } else {
            self.dropped += 1;
            if self.dropped == 1 || self.dropped.is_multiple_of(1000) {
                tracing::warn!(
                    "mtk-dma RX overflow buffer full ({} dropped)",
                    self.dropped
                );
            }
        }
    }
}

fn tx_rate_params(rate: TxRate) -> (u8, u8, u8, u8, u8) {
    match rate {
        TxRate::Legacy(r) => (0u8, (r / 2).max(6), 1u8, 0u8, 0u8),
        TxRate::Ht { mcs, sgi } => (1u8, mcs, 1u8, 0u8, if sgi { 1 } else { 0 }),
        TxRate::Vht {
            mcs,
            nss,
            bw_mhz,
            sgi,
        } => {
            let bw_code = match bw_mhz {
                80 => 2u8,
                40 => 1u8,
                _ => 0u8,
            };
            (2u8, mcs, nss, bw_code, if sgi { 1 } else { 0 })
        }
    }
}

#[allow(unsafe_code)]
unsafe extern "C" fn direct_mtk_rx_cb(
    frame: *const u8,
    len: usize,
    rssi: i8,
    ctx: *mut c_void,
) {
    if frame.is_null() || !(16..=MTK_MAX_RX_FRAME).contains(&len) || ctx.is_null() {
        return;
    }
    let bridge = unsafe { &mut *(ctx as *mut RxBridge) };
    let slice = unsafe { std::slice::from_raw_parts(frame, len) };
    bridge.push(Received {
        bytes: slice.to_vec(),
        rssi: Some(rssi),
    });
}

/// Direct single-process `Air` backed by `mtkradio_core.dll` (MT7922 32-bit DMA
/// directly inside `owly.exe`, zero Named Pipe IPC and zero radiotap overhead).
struct DirectMtkAir {
    rx: mpsc::Receiver<Received>,
    tx: std::sync::mpsc::SyncSender<Frame>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl DirectMtkAir {
    fn open(fw_dir: &str, channel: u8, width_mhz: u32, own_mac: [u8; 6]) -> io::Result<Self> {
        let dll = MtkCoreDll::load()?;
        let fw_cstr = CString::new(fw_dir)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid firmware path"))?;
        let verbose = std::env::var("OWLY_MTK_VERBOSE")
            .map(|v| v.trim() == "1")
            .unwrap_or(true);

        let (rx_tx, rx_rx) = mpsc::channel::<Received>(2048);
        let (tx_tx, tx_rx) = std::sync::mpsc::sync_channel::<Frame>(2048);
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<Result<(), String>>(1);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_bg = Arc::clone(&stop);

        let worker = thread::Builder::new()
            .name("mtk-dma".into())
            .spawn(move || {
                let mut err_buf = [0i8; 256];
                #[allow(unsafe_code)]
                let handle = unsafe {
                    (dll.open)(
                        fw_cstr.as_ptr(),
                        channel,
                        width_mhz,
                        own_mac.as_ptr(),
                        AWDL_BSSID.as_ptr(),
                        if verbose { 1 } else { 0 },
                        Some(direct_mtk_log_cb),
                        ptr::null_mut(),
                        err_buf.as_mut_ptr(),
                        err_buf.len(),
                    )
                };
                if handle.is_null() {
                    #[allow(unsafe_code)]
                    let msg = unsafe { CStr::from_ptr(err_buf.as_ptr()) }
                        .to_string_lossy()
                        .into_owned();
                    let _ = ready_tx.send(Err(if msg.is_empty() {
                        "mtk_open failed".into()
                    } else {
                        msg
                    }));
                    return;
                }
                let _ = ready_tx.send(Ok(()));

                let mut last_active = Instant::now();
                let spin_window = Duration::from_millis(5);
                let mut rx_bridge = RxBridge::new(rx_tx);
                let mut pending_tx: Option<(Frame, Instant)> = None;

                while !stop_bg.load(Ordering::Relaxed) {
                    rx_bridge.drain();
                    let mut tx_sent = 0usize;
                    let mut total_rx = 0usize;
                    for _ in 0..256 {
                        let (frame, first_try) = match pending_tx.take() {
                            Some(item) => item,
                            None => match tx_rx.try_recv() {
                                Ok(f) => (f, Instant::now()),
                                Err(_) => break,
                            },
                        };
                        if frame.bytes.len() < 16 {
                            tracing::warn!(
                                "mtk-dma skipping short TX frame ({} bytes)",
                                frame.bytes.len()
                            );
                            continue;
                        }
                        let (rate_mode, rate_val, nss, bw, sgi) = tx_rate_params(frame.rate);
                        let no_ack = if frame.no_ack { 1u8 } else { 0u8 };
                        #[allow(unsafe_code)]
                        let ok = unsafe {
                            (dll.transmit)(
                                handle,
                                frame.bytes.as_ptr(),
                                frame.bytes.len(),
                                rate_mode,
                                rate_val,
                                nss,
                                bw,
                                sgi,
                                no_ack,
                                0, // batch kick below
                            )
                        };
                        if ok != 0 {
                            tx_sent += 1;
                            continue;
                        }

                        // Hardware 64-token TX_FREE pool or 256-slot TX DMA ring is full.
                        // Kick any already-queued frames immediately so hardware starts
                        // draining them, then poll `mtk_poll` (reclaiming TX_FREE tokens
                        // and capturing all RX frames into `rx_bridge`) and retry briefly.
                        if tx_sent > 0 {
                            #[allow(unsafe_code)]
                            unsafe {
                                (dll.kick_tx)(handle);
                            }
                            tx_sent = 0;
                        }

                        let mut queued = false;
                        for attempt in 0..TX_BACKPRESSURE_INLINE_RETRIES {
                            let rx_ctx = (&mut rx_bridge as *mut RxBridge) as *mut c_void;
                            #[allow(unsafe_code)]
                            let got =
                                unsafe { (dll.poll)(handle, Some(direct_mtk_rx_cb), rx_ctx) };
                            total_rx += got;
                            rx_bridge.drain();

                            #[allow(unsafe_code)]
                            let retry_ok = unsafe {
                                (dll.transmit)(
                                    handle,
                                    frame.bytes.as_ptr(),
                                    frame.bytes.len(),
                                    rate_mode,
                                    rate_val,
                                    nss,
                                    bw,
                                    sgi,
                                    no_ack,
                                    0,
                                )
                            };
                            if retry_ok != 0 {
                                tx_sent += 1;
                                queued = true;
                                break;
                            }
                            if attempt < TX_BACKPRESSURE_INLINE_RETRIES / 2 {
                                std::hint::spin_loop();
                            } else {
                                thread::yield_now();
                            }
                        }

                        if !queued {
                            if first_try.elapsed() >= TX_BACKPRESSURE_MAX_WAIT {
                                tracing::warn!(
                                    "mtk-dma TX frame timed out waiting for TX_FREE/DMA slot (len={})",
                                    frame.bytes.len()
                                );
                            } else {
                                pending_tx = Some((frame, first_try));
                                break;
                            }
                        }
                    }
                    if tx_sent > 0 {
                        #[allow(unsafe_code)]
                        unsafe {
                            (dll.kick_tx)(handle);
                        }
                    }

                    let rx_ctx = (&mut rx_bridge as *mut RxBridge) as *mut c_void;
                    #[allow(unsafe_code)]
                    let rx_got = unsafe { (dll.poll)(handle, Some(direct_mtk_rx_cb), rx_ctx) };
                    total_rx += rx_got;
                    rx_bridge.drain();

                    if let Some((_, first_try)) = &pending_tx {
                        last_active = Instant::now();
                        if first_try.elapsed() > Duration::from_millis(2) {
                            thread::sleep(Duration::from_micros(100));
                        } else {
                            thread::yield_now();
                        }
                    } else if tx_sent > 0 || total_rx > 0 || !rx_bridge.overflow.is_empty() {
                        last_active = Instant::now();
                    } else if last_active.elapsed() < spin_window {
                        thread::yield_now();
                    } else {
                        thread::sleep(Duration::from_millis(1));
                    }
                }

                #[allow(unsafe_code)]
                unsafe {
                    (dll.close)(handle);
                }
            })?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                rx: rx_rx,
                tx: tx_tx,
                stop,
                worker: Some(worker),
            }),
            Ok(Err(msg)) => {
                let _ = worker.join();
                Err(io::Error::other(format!("mtkradio_core open failed: {msg}")))
            }
            Err(_) => {
                let _ = worker.join();
                Err(io::Error::other("mtk-dma thread exited during open"))
            }
        }
    }
}

impl Drop for DirectMtkAir {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
    }
}

impl Air for DirectMtkAir {
    async fn recv(&mut self) -> io::Result<Received> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "mtk-dma thread stopped"))
    }

    fn try_recv(&mut self) -> Option<Received> {
        self.rx.try_recv().ok()
    }

    fn send(&mut self, frame: Frame) -> Result<(), Frame> {
        match self.tx.try_send(frame) {
            Ok(()) => Ok(()),
            Err(std::sync::mpsc::TrySendError::Full(f)) => Err(f),
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Wintun Layer-3 IPv6 Netif
// ---------------------------------------------------------------------------

type WintunCreateAdapterFn =
    unsafe extern "system" fn(*const u16, *const u16, *const u8) -> HANDLE;
type WintunCloseAdapterFn = unsafe extern "system" fn(HANDLE);
type WintunGetAdapterLuidFn = unsafe extern "system" fn(HANDLE, *mut u64);
type WintunStartSessionFn = unsafe extern "system" fn(HANDLE, u32) -> HANDLE;
type WintunEndSessionFn = unsafe extern "system" fn(HANDLE);
type WintunGetReadWaitEventFn = unsafe extern "system" fn(HANDLE) -> HANDLE;
type WintunReceivePacketFn = unsafe extern "system" fn(HANDLE, *mut u32) -> *mut u8;
type WintunReleaseReceivePacketFn = unsafe extern "system" fn(HANDLE, *const u8);
type WintunAllocateSendPacketFn = unsafe extern "system" fn(HANDLE, u32) -> *mut u8;
type WintunSendPacketFn = unsafe extern "system" fn(HANDLE, *const u8);

struct WintunDll {
    module: HMODULE,
    create_adapter: WintunCreateAdapterFn,
    close_adapter: WintunCloseAdapterFn,
    get_adapter_luid: WintunGetAdapterLuidFn,
    start_session: WintunStartSessionFn,
    end_session: WintunEndSessionFn,
    get_read_wait_event: WintunGetReadWaitEventFn,
    receive_packet: WintunReceivePacketFn,
    release_receive_packet: WintunReleaseReceivePacketFn,
    allocate_send_packet: WintunAllocateSendPacketFn,
    send_packet: WintunSendPacketFn,
}

#[allow(unsafe_code)]
// SAFETY: `WintunDll` holds a loaded DLL handle and immutable function pointers
// valid until `FreeLibrary` runs when the last `Arc<WintunDll>` is dropped.
unsafe impl Send for WintunDll {}
#[allow(unsafe_code)]
// SAFETY: Wintun exported functions are thread-safe per the Wintun API contract.
unsafe impl Sync for WintunDll {}

impl Drop for WintunDll {
    fn drop(&mut self) {
        if !self.module.is_null() {
            #[allow(unsafe_code)]
            // SAFETY: `self.module` was returned by `LoadLibraryW` and is freed once.
            unsafe {
                FreeLibrary(self.module);
            }
        }
    }
}

impl WintunDll {
    fn load() -> io::Result<Arc<Self>> {
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Some(p) = std::env::var_os("OWLY_WINTUN_DLL") {
            candidates.push(PathBuf::from(p));
        }
        if let Ok(exe) = std::env::current_exe()
            && let Some(dir) = exe.parent()
        {
            candidates.push(dir.join("wintun.dll"));
        }
        candidates.push(PathBuf::from("wintun.dll"));
        candidates.push(PathBuf::from(
            r"..\nekodrop-0.1.21-windows-x64\awdl\wintun.dll",
        ));
        candidates.push(PathBuf::from(
            r"C:\Users\20662\Desktop\MTKAWDL\nekodrop-0.1.21-windows-x64\awdl\wintun.dll",
        ));

        let mut module: HMODULE = ptr::null_mut();
        for path in &candidates {
            if path.is_absolute() && !path.exists() {
                continue;
            }
            let wide = to_wide_os(path);
            #[allow(unsafe_code)]
            // SAFETY: `wide` is NUL-terminated UTF-16.
            let h = unsafe { LoadLibraryW(wide.as_ptr()) };
            if !h.is_null() {
                tracing::info!("loaded wintun.dll from {}", path.display());
                module = h;
                break;
            }
        }
        if module.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "could not load wintun.dll (place wintun.dll next to owly.exe or set OWLY_WINTUN_DLL)",
            ));
        }

        macro_rules! load_sym {
            ($name:literal, $ty:ty) => {{
                #[allow(unsafe_code)]
                // SAFETY: `module` is a valid loaded DLL and `$name` is NUL-terminated ASCII.
                let proc = unsafe { GetProcAddress(module, concat!($name, "\0").as_ptr()) };
                let Some(f) = proc else {
                    #[allow(unsafe_code)]
                    unsafe {
                        FreeLibrary(module);
                    }
                    return Err(io::Error::other(concat!("missing symbol in wintun.dll: ", $name)));
                };
                #[allow(unsafe_code)]
                // SAFETY: Signature matches `wintun.h`.
                unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(f) }
            }};
        }

        Ok(Arc::new(Self {
            module,
            create_adapter: load_sym!("WintunCreateAdapter", WintunCreateAdapterFn),
            close_adapter: load_sym!("WintunCloseAdapter", WintunCloseAdapterFn),
            get_adapter_luid: load_sym!("WintunGetAdapterLUID", WintunGetAdapterLuidFn),
            start_session: load_sym!("WintunStartSession", WintunStartSessionFn),
            end_session: load_sym!("WintunEndSession", WintunEndSessionFn),
            get_read_wait_event: load_sym!("WintunGetReadWaitEvent", WintunGetReadWaitEventFn),
            receive_packet: load_sym!("WintunReceivePacket", WintunReceivePacketFn),
            release_receive_packet: load_sym!(
                "WintunReleaseReceivePacket",
                WintunReleaseReceivePacketFn
            ),
            allocate_send_packet: load_sym!("WintunAllocateSendPacket", WintunAllocateSendPacketFn),
            send_packet: load_sym!("WintunSendPacket", WintunSendPacketFn),
        }))
    }
}

#[derive(Clone, Copy)]
struct SendHandle(HANDLE);

#[allow(unsafe_code)]
// SAFETY: Win32 handles (Wintun adapter/session and Win32 events) can be passed across threads.
unsafe impl Send for SendHandle {}

struct WintunAdapter {
    dll: Arc<WintunDll>,
    adapter: SendHandle,
    index: u32,
}

impl WintunAdapter {
    fn create(name: &str, link_local: Ipv6Addr, mtu: u32) -> io::Result<Self> {
        let dll = WintunDll::load()?;
        let name_w = to_wide(name);
        let tunnel_w = to_wide("Owly");

        #[allow(unsafe_code)]
        // SAFETY: `name_w` and `tunnel_w` are NUL-terminated UTF-16 strings.
        let adapter = unsafe { (dll.create_adapter)(name_w.as_ptr(), tunnel_w.as_ptr(), ptr::null()) };
        if adapter.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "WintunCreateAdapter({name:?}) failed: {} (run as Administrator)",
                    io::Error::last_os_error()
                ),
            ));
        }

        let mut luid_val: u64 = 0;
        #[allow(unsafe_code)]
        // SAFETY: `adapter` is valid and `luid_val` is writable.
        unsafe {
            (dll.get_adapter_luid)(adapter, &mut luid_val);
        }
        let luid = NET_LUID_LH { Value: luid_val };

        let mut index: u32 = 0;
        #[allow(unsafe_code)]
        // SAFETY: `luid` and `index` are valid pointers.
        let err = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
        if err != NO_ERROR {
            #[allow(unsafe_code)]
            unsafe {
                (dll.close_adapter)(adapter);
            }
            return Err(io::Error::from_raw_os_error(err as i32));
        }

        if let Err(e) = configure_ipv6_interface(luid, link_local, mtu) {
            #[allow(unsafe_code)]
            unsafe {
                (dll.close_adapter)(adapter);
            }
            return Err(e);
        }

        Ok(Self {
            dll,
            adapter: SendHandle(adapter),
            index,
        })
    }
}

fn configure_ipv6_interface(luid: NET_LUID_LH, link_local: Ipv6Addr, mtu: u32) -> io::Result<()> {
    // 1. Set MTU (default 1500, overrideable via OWLY_MTU) and disable DAD on IPv6.
    #[allow(unsafe_code)]
    // SAFETY: `MIB_IPINTERFACE_ROW` is a plain C struct initialized before `GetIpInterfaceEntry`.
    let mut iface_row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    iface_row.Family = AF_INET6;
    iface_row.InterfaceLuid = luid;
    #[allow(unsafe_code)]
    // SAFETY: `iface_row` has `Family` and `InterfaceLuid` set.
    let err = unsafe { GetIpInterfaceEntry(&mut iface_row) };
    if err == NO_ERROR {
        iface_row.NlMtu = mtu;
        iface_row.DadTransmits = 0;
        iface_row.SitePrefixLength = 0;
        #[allow(unsafe_code)]
        // SAFETY: `iface_row` was populated by `GetIpInterfaceEntry`.
        let set_err = unsafe { SetIpInterfaceEntry(&mut iface_row) };
        if set_err != NO_ERROR {
            tracing::warn!("SetIpInterfaceEntry(MTU={mtu}) returned error {set_err}");
        } else {
            tracing::info!("configured Wintun IPv6 MTU={mtu} (DAD disabled)");
        }
    } else {
        tracing::warn!("GetIpInterfaceEntry returned error {err}");
    }

    // 2. Remove any auto-generated IPv6 link-local addresses on this adapter
    //    so only our AWDL EUI-64 address is present (NET-1).
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = ptr::null_mut();
    #[allow(unsafe_code)]
    // SAFETY: `table` receives a MIB table freed with `FreeMibTable`.
    let err = unsafe { GetUnicastIpAddressTable(AF_INET6, &mut table) };
    if err == NO_ERROR && !table.is_null() {
        #[allow(unsafe_code)]
        // SAFETY: `table` is valid on `NO_ERROR`.
        unsafe {
            let rows =
                std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
            let target = luid.Value;
            for row in rows {
                if row.InterfaceLuid.Value == target {
                    let bytes = row.Address.Ipv6.sin6_addr.u.Byte;
                    if Ipv6Addr::from(bytes) != link_local {
                        let _ = DeleteUnicastIpAddressEntry(row);
                    }
                }
            }
            FreeMibTable(table.cast());
        }
    }

    // 3. Add our EUI-64 link-local address as preferred immediately.
    #[allow(unsafe_code)]
    // SAFETY: `MIB_UNICASTIPADDRESS_ROW` is initialized by `InitializeUnicastIpAddressEntry`.
    let mut addr_row: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
    #[allow(unsafe_code)]
    // SAFETY: `addr_row` is valid writable memory.
    unsafe {
        InitializeUnicastIpAddressEntry(&mut addr_row);
    }
    addr_row.InterfaceLuid = luid;
    addr_row.Address.si_family = AF_INET6;
    addr_row.Address.Ipv6.sin6_family = AF_INET6;
    addr_row.Address.Ipv6.sin6_addr.u.Byte = link_local.octets();
    addr_row.OnLinkPrefixLength = 64;
    addr_row.PrefixOrigin = IpPrefixOriginManual;
    addr_row.SuffixOrigin = IpSuffixOriginManual;
    addr_row.DadState = IpDadStatePreferred;

    #[allow(unsafe_code)]
    // SAFETY: `addr_row` is fully initialized.
    let err = unsafe { CreateUnicastIpAddressEntry(&addr_row) };
    if err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS {
        return Err(io::Error::from_raw_os_error(err as i32));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Wintun Software GRO (IPv6/TCP receive segment coalescing)
// ---------------------------------------------------------------------------

const IPV6_HEADER_LEN: usize = 40;
const TCP_MIN_HEADER_LEN: usize = 20;
const IPPROTO_TCP: u8 = 6;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;
/// Maximum consecutive TCP segments merged into one Wintun packet.
const GRO_MAX_SEGMENTS: usize = 16;
/// Maximum total IPv6 packet size (header + merged TCP payload) per GRO batch (~24 KiB).
const GRO_MAX_BYTES: usize = 24 * 1024;
/// Maximum hold age for a buffered batch before flushing so ACK latency never stalls.
const GRO_MAX_HOLD: Duration = Duration::from_micros(500);
const GRO_STATS_INTERVAL: Duration = Duration::from_secs(10);

#[inline]
fn sum_be_u16_words(mut sum: u64, data: &[u8]) -> u64 {
    let (chunks, rem) = data.as_chunks::<2>();
    for &pair in chunks {
        sum += u16::from_be_bytes(pair) as u64;
    }
    if let Some(&last) = rem.first() {
        sum += ((last as u16) << 8) as u64;
    }
    sum
}

/// Computes the RFC 2460 IPv6 TCP checksum over `packet` (assuming no IPv6
/// extension headers, `packet[6] == 6`, `packet.len() >= 60`), treating the
/// wire checksum field `packet[56..58]` as zero.
fn compute_ipv6_tcp_checksum(packet: &[u8]) -> u16 {
    debug_assert!(packet.len() >= IPV6_HEADER_LEN + TCP_MIN_HEADER_LEN);
    let tcp_len = packet.len() - IPV6_HEADER_LEN;
    let mut sum: u64 = 0;

    // Pseudo-header: src + dst IPv6 (32 bytes), upper-layer TCP length (u32 BE), next_hdr (6).
    sum = sum_be_u16_words(sum, &packet[8..40]);
    sum += (tcp_len >> 16) as u64;
    sum += (tcp_len & 0xffff) as u64;
    sum += u64::from(IPPROTO_TCP);

    // TCP header + payload with checksum field [56..58] treated as zero.
    sum = sum_be_u16_words(sum, &packet[40..56]);
    sum = sum_be_u16_words(sum, &packet[58..]);

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[derive(Clone, Copy)]
struct TcpSegMeta {
    header_offset: usize,
    payload_len: usize,
    seq: u32,
    flags: u8,
}

/// Returns `Some(meta)` if `packet` is a valid, checksum-verified IPv6/TCP
/// data segment eligible for Software GRO coalescing.
fn parse_coalescable_tcp(packet: &[u8]) -> Option<TcpSegMeta> {
    if packet.len() < IPV6_HEADER_LEN + TCP_MIN_HEADER_LEN {
        return None;
    }
    // IPv6 version == 6, Next Header == TCP (no extension headers).
    if (packet[0] >> 4) != 6 || packet[6] != IPPROTO_TCP {
        return None;
    }
    // IPv6 payload length must exactly match packet length - 40.
    let ipv6_payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if ipv6_payload_len != packet.len() - IPV6_HEADER_LEN {
        return None;
    }
    // Reserved/NS bits in data-offset byte must be zero; urgent pointer must be zero.
    if (packet[52] & 0x0f) != 0 || packet[58] != 0 || packet[59] != 0 {
        return None;
    }
    let tcp_hdr_len = ((packet[52] >> 4) as usize) * 4;
    if tcp_hdr_len < TCP_MIN_HEADER_LEN {
        return None;
    }
    let header_offset = IPV6_HEADER_LEN + tcp_hdr_len;
    if packet.len() <= header_offset {
        // Pure ACK or zero-payload segment: bypass GRO.
        return None;
    }
    // Only ACK or ACK|PSH data segments may be coalesced (SYN/FIN/RST/URG/ECE/CWR bypass).
    let flags = packet[53];
    if flags != TCP_ACK && flags != (TCP_ACK | TCP_PSH) {
        return None;
    }
    // Verify the incoming TCP checksum so corrupted segments are never masked by re-checksumming.
    let wire_csum = u16::from_be_bytes([packet[56], packet[57]]);
    if compute_ipv6_tcp_checksum(packet) != wire_csum {
        return None;
    }
    let seq = u32::from_be_bytes([packet[44], packet[45], packet[46], packet[47]]);
    Some(TcpSegMeta {
        header_offset,
        payload_len: packet.len() - header_offset,
        seq,
        flags,
    })
}

/// Checks whether `next` is strictly contiguous with `prev` on the same TCP flow
/// and shares compatible headers/options.
fn is_contiguous_tcp(
    prev: &[u8],
    next: &[u8],
    offset: usize,
    expected_seq: u32,
    next_seq: u32,
) -> bool {
    if next_seq != expected_seq {
        return false;
    }
    // Version/TC/FlowLabel, NextHdr/HopLimit/SrcIP/DstIP/SrcPort/DstPort, AckNum/DataOff, Window.
    if prev[0..4] != next[0..4]
        || prev[6..44] != next[6..44]
        || prev[48..53] != next[48..53]
        || prev[54..56] != next[54..56]
    {
        return false;
    }
    if offset > IPV6_HEADER_LEN + TCP_MIN_HEADER_LEN {
        // Apple iOS/macOS TCP segments typically carry 12-byte NOP+NOP+Timestamp options.
        // Allow TSval to stay equal or advance monotonically while requiring identical TSecr.
        if offset == 72
            && prev[60..64] == [0x01, 0x01, 0x08, 0x0a]
            && next[60..64] == [0x01, 0x01, 0x08, 0x0a]
        {
            if prev[68..72] != next[68..72] {
                return false;
            }
            let prev_ts = u32::from_be_bytes([prev[64], prev[65], prev[66], prev[67]]);
            let next_ts = u32::from_be_bytes([next[64], next[65], next[66], next[67]]);
            if next_ts.wrapping_sub(prev_ts) >= 0x8000_0000 {
                return false;
            }
        } else if prev[60..offset] != next[60..offset] {
            return false;
        }
    }
    true
}

/// Software GRO coalescer for inbound IPv6/TCP data segments delivered to Wintun.
///
/// Merges up to 16 consecutive in-order segments (up to ~24 KiB) from the same
/// TCP flow into a single large IPv6/TCP packet with recomputed checksum,
/// reducing Windows `tcpip.sys` per-packet processing overhead by 8-16x while
/// preserving strict packet ordering and bounded latency (`<= 500 us`).
struct TcpCoalescer {
    enabled: bool,
    pending: Vec<Ipv6Packet>,
    header_offset: usize,
    merged_len: usize,
    next_seq: u32,
    has_psh: bool,
    started_at: Instant,
    coalesced_buf: Vec<u8>,
    in_segs: u64,
    out_pkts: u64,
    fallbacks: u64,
    last_stats_log: Instant,
}

impl TcpCoalescer {
    fn new(enabled: bool) -> Self {
        let now = Instant::now();
        Self {
            enabled,
            pending: Vec::with_capacity(GRO_MAX_SEGMENTS),
            header_offset: 0,
            merged_len: 0,
            next_seq: 0,
            has_psh: false,
            started_at: now,
            coalesced_buf: Vec::with_capacity(GRO_MAX_BYTES),
            in_segs: 0,
            out_pkts: 0,
            fallbacks: 0,
            last_stats_log: now,
        }
    }

    /// Offers an inbound IPv6 packet, calling `send_raw` whenever packets are
    /// ready to be injected into Wintun. `send_raw` returns `true` if Wintun
    /// accepted the packet and `false` if allocation failed (triggering fallback
    /// to individual segments for coalesced batches).
    fn offer<F>(&mut self, packet: Ipv6Packet, now: Instant, mut send_raw: F)
    where
        F: FnMut(&[u8]) -> bool,
    {
        if !self.enabled {
            let _ = send_raw(&packet.data);
            return;
        }

        if !self.pending.is_empty() && now.saturating_duration_since(self.started_at) >= GRO_MAX_HOLD
        {
            self.flush(&mut send_raw);
        }

        let Some(meta) = parse_coalescable_tcp(&packet.data) else {
            // Non-TCP, pure ACK, SYN/FIN/RST, or invalid checksum: flush pending in order first.
            if !self.pending.is_empty() {
                self.flush(&mut send_raw);
            }
            let _ = send_raw(&packet.data);
            return;
        };

        if let Some(prev) = self.pending.last() {
            let fits_size = self.merged_len + meta.payload_len <= GRO_MAX_BYTES
                && (self.merged_len + meta.payload_len - IPV6_HEADER_LEN) <= u16::MAX as usize;
            let same_offset = self.header_offset == meta.header_offset;
            if !fits_size
                || !same_offset
                || !is_contiguous_tcp(
                    &prev.data,
                    &packet.data,
                    meta.header_offset,
                    self.next_seq,
                    meta.seq,
                )
            {
                self.flush(&mut send_raw);
            }
        }

        if self.pending.is_empty() {
            self.started_at = now;
            self.header_offset = meta.header_offset;
            self.merged_len = meta.header_offset;
            self.has_psh = false;
        }

        self.pending.push(packet);
        self.merged_len += meta.payload_len;
        self.next_seq = meta.seq.wrapping_add(meta.payload_len as u32);
        self.has_psh |= (meta.flags & TCP_PSH) != 0;

        if self.pending.len() >= GRO_MAX_SEGMENTS
            || (meta.flags & TCP_PSH) != 0
            || self.merged_len >= GRO_MAX_BYTES
        {
            self.flush(&mut send_raw);
        }
    }

    /// Flushes any buffered batch immediately (called at end of each RX burst
    /// and on timer ticks via `Netif::flush_inbound`).
    fn flush<F>(&mut self, mut send_raw: F)
    where
        F: FnMut(&[u8]) -> bool,
    {
        let count = self.pending.len();
        if count == 0 {
            return;
        }
        self.in_segs += count as u64;

        if count == 1 {
            let _ = send_raw(&self.pending[0].data);
            self.out_pkts += 1;
        } else {
            let offset = self.header_offset;
            let first_seq = &self.pending[0].data[44..48];
            let last_hdr = &self.pending[count - 1].data[..offset];

            self.coalesced_buf.clear();
            self.coalesced_buf.extend_from_slice(last_hdr);
            self.coalesced_buf[44..48].copy_from_slice(first_seq);
            if self.has_psh {
                self.coalesced_buf[53] |= TCP_PSH;
            }
            for seg in &self.pending {
                self.coalesced_buf.extend_from_slice(&seg.data[offset..]);
            }
            let ipv6_payload_len = (self.coalesced_buf.len() - IPV6_HEADER_LEN) as u16;
            self.coalesced_buf[4..6].copy_from_slice(&ipv6_payload_len.to_be_bytes());
            let csum = compute_ipv6_tcp_checksum(&self.coalesced_buf);
            self.coalesced_buf[56..58].copy_from_slice(&csum.to_be_bytes());

            if send_raw(&self.coalesced_buf) {
                self.out_pkts += 1;
            } else {
                // WintunAllocateSendPacket failed on coalesced packet: fall back to individual segments.
                self.fallbacks += 1;
                for seg in &self.pending {
                    let _ = send_raw(&seg.data);
                }
                self.out_pkts += count as u64;
            }
        }

        self.pending.clear();
        self.merged_len = 0;
        self.has_psh = false;

        if self.last_stats_log.elapsed() >= GRO_STATS_INTERVAL && self.in_segs > 0 {
            let ratio = self.in_segs as f64 / self.out_pkts.max(1) as f64;
            tracing::info!(
                "[wintun-gro] segs={} -> pkts={} ({:.2}x coalesce, fallbacks={})",
                self.in_segs,
                self.out_pkts,
                ratio,
                self.fallbacks
            );
            self.last_stats_log = Instant::now();
        }
    }
}

struct WintunNetif {
    dll: Arc<WintunDll>,
    adapter: SendHandle,
    session: SendHandle,
    stop_event: SendHandle,
    rx: Option<mpsc::Receiver<Ipv6Packet>>,
    rx_thread: Option<JoinHandle<()>>,
    coalescer: TcpCoalescer,
}

impl WintunNetif {
    fn start(adapter: WintunAdapter) -> io::Result<Self> {
        let WintunAdapter { dll, adapter, .. } = adapter;

        #[allow(unsafe_code)]
        // SAFETY: `adapter.0` is a valid Wintun adapter handle.
        let session = unsafe { (dll.start_session)(adapter.0, WINTUN_RING_CAPACITY) };
        if session.is_null() {
            #[allow(unsafe_code)]
            unsafe {
                (dll.close_adapter)(adapter.0);
            }
            return Err(io::Error::last_os_error());
        }

        #[allow(unsafe_code)]
        // SAFETY: Creating an unnamed manual-reset Win32 event.
        let stop_event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if stop_event.is_null() {
            #[allow(unsafe_code)]
            unsafe {
                (dll.end_session)(session);
                (dll.close_adapter)(adapter.0);
            }
            return Err(io::Error::last_os_error());
        }

        #[allow(unsafe_code)]
        // SAFETY: `session` is a valid Wintun session handle.
        let read_event = SendHandle(unsafe { (dll.get_read_wait_event)(session) });
        let session_h = SendHandle(session);
        let stop_h = SendHandle(stop_event);
        let dll_rx = Arc::clone(&dll);
        let (tx, rx) = mpsc::channel::<Ipv6Packet>(WINTUN_RX_QUEUE_CAP);

        let rx_thread = thread::Builder::new()
            .name("wintun-rx".into())
            .spawn(move || {
                let (read_event, stop_h, session_h) = (read_event, stop_h, session_h);
                let handles = [read_event.0, stop_h.0];
                loop {
                    let mut size: u32 = 0;
                    #[allow(unsafe_code)]
                    // SAFETY: `session_h.0` is valid until `rx_thread` is joined in `Drop`.
                    let ptr = unsafe { (dll_rx.receive_packet)(session_h.0, &mut size) };
                    if !ptr.is_null() {
                        #[allow(unsafe_code)]
                        // SAFETY: `ptr` points to `size` bytes valid until `release_receive_packet`.
                        let bytes = unsafe { std::slice::from_raw_parts(ptr, size as usize) };
                        let pkt = if bytes.len() >= 40 && (bytes[0] >> 4) == 6 {
                            Ipv6Packet::from_ip(bytes.to_vec())
                        } else {
                            None
                        };
                        #[allow(unsafe_code)]
                        // SAFETY: `ptr` was returned by `receive_packet`.
                        unsafe {
                            (dll_rx.release_receive_packet)(session_h.0, ptr);
                        }
                        if let Some(pkt) = pkt {
                            // Apply lossless backpressure instead of silently dropping
                            // outbound TCP bursts when `owly-awdl` pauses between slots.
                            if tx.blocking_send(pkt).is_err() {
                                break;
                            }
                        }
                        continue;
                    }

                    let err = io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
                    if err != ERROR_NO_MORE_ITEMS {
                        tracing::warn!("WintunReceivePacket failed with Win32 error {err}");
                        break;
                    }

                    #[allow(unsafe_code)]
                    // SAFETY: `handles` contains two valid Win32 event handles.
                    let waited = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) };
                    if waited == WAIT_OBJECT_0 {
                        continue;
                    }
                    // `stop_event` signaled or wait failed.
                    break;
                }
            })?;

        let use_gro = gro_enabled();
        tracing::info!("WintunNetif started (Software GRO={use_gro})");

        Ok(Self {
            dll,
            adapter,
            session: session_h,
            stop_event: stop_h,
            rx: Some(rx),
            rx_thread: Some(rx_thread),
            coalescer: TcpCoalescer::new(use_gro),
        })
    }

    #[inline]
    fn inject_raw(dll: &WintunDll, session: SendHandle, data: &[u8]) -> bool {
        let len = data.len();
        if len == 0 || len > u32::MAX as usize {
            return false;
        }
        #[allow(unsafe_code)]
        // SAFETY: `session.0` is valid for the lifetime of `WintunNetif`.
        unsafe {
            let dst = (dll.allocate_send_packet)(session.0, len as u32);
            if dst.is_null() {
                return false;
            }
            ptr::copy_nonoverlapping(data.as_ptr(), dst, len);
            (dll.send_packet)(session.0, dst);
            true
        }
    }
}

impl Netif for WintunNetif {
    async fn recv(&mut self) -> io::Result<Ipv6Packet> {
        let Some(rx) = self.rx.as_mut() else {
            return Err(io::Error::other("wintun adapter closed"));
        };
        rx.recv()
            .await
            .ok_or_else(|| io::Error::other("wintun adapter closed"))
    }

    fn try_recv(&mut self) -> Option<Ipv6Packet> {
        self.rx.as_mut()?.try_recv().ok()
    }

    fn deliver(&mut self, packet: Ipv6Packet) {
        let dll = &self.dll;
        let session = self.session;
        self.coalescer.offer(packet, Instant::now(), |raw| {
            Self::inject_raw(dll, session, raw)
        });
    }

    fn flush_inbound(&mut self) {
        let dll = &self.dll;
        let session = self.session;
        self.coalescer
            .flush(|raw| Self::inject_raw(dll, session, raw));
    }
}

impl Drop for WintunNetif {
    fn drop(&mut self) {
        // Close the receiver first so a blocked `tx.blocking_send` wakes immediately.
        drop(self.rx.take());
        #[allow(unsafe_code)]
        // SAFETY: Signaling `stop_event` wakes `rx_thread` so it exits before
        // `end_session` and `close_adapter` run.
        unsafe {
            SetEvent(self.stop_event.0);
        }
        if let Some(t) = self.rx_thread.take() {
            let _ = t.join();
        }
        #[allow(unsafe_code)]
        // SAFETY: `rx_thread` has exited; handles are closed once in reverse order.
        unsafe {
            (self.dll.end_session)(self.session.0);
            (self.dll.close_adapter)(self.adapter.0);
            CloseHandle(self.stop_event.0);
        }
    }
}

/// Permanently removes (`SE_PRIVILEGE_REMOVED`) all privileges from the current
/// process token once hardware DMA pages and Wintun have been initialized, so
/// network/TLS processing runs without `SeDebugPrivilege`, `SeTcbPrivilege`,
/// `SeLockMemoryPrivilege`, `SeTakeOwnershipPrivilege`, etc.
fn drop_process_privileges() {
    #[allow(unsafe_code)]
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
            || token.is_null()
        {
            return;
        }

        let mut needed: u32 = 0;
        let _ = GetTokenInformation(token, TokenPrivileges, ptr::null_mut(), 0, &mut needed);
        if needed >= size_of::<TOKEN_PRIVILEGES>() as u32 {
            let mut buf = vec![0u8; needed as usize];
            if GetTokenInformation(
                token,
                TokenPrivileges,
                buf.as_mut_ptr().cast(),
                needed,
                &mut needed,
            ) != 0
            {
                let tp = &mut *(buf.as_mut_ptr() as *mut TOKEN_PRIVILEGES);
                let count = tp.PrivilegeCount as usize;
                let items = std::slice::from_raw_parts_mut(tp.Privileges.as_mut_ptr(), count);
                for item in items.iter_mut() {
                    item.Attributes = SE_PRIVILEGE_REMOVED;
                }
                let ok = AdjustTokenPrivileges(
                    token,
                    0,
                    buf.as_ptr().cast(),
                    needed,
                    ptr::null_mut(),
                    ptr::null_mut(),
                );
                if ok != 0 {
                    tracing::info!(
                        "[security] permanently removed {} privileges (SE_PRIVILEGE_REMOVED) after hardware init",
                        count
                    );
                }
            }
        }
        let _ = std::mem::size_of::<LUID_AND_ATTRIBUTES>();
        CloseHandle(token);
    }
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn to_wide_os(p: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    p.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_tx_radiotap_matches_radiotap_tx_header() {
        for rate in [
            TxRate::Legacy(12),
            TxRate::Legacy(24),
            TxRate::Legacy(108),
            TxRate::Ht { mcs: 0, sgi: false },
            TxRate::Ht { mcs: 7, sgi: true },
            TxRate::Ht { mcs: 15, sgi: true },
            TxRate::Vht {
                mcs: 7,
                nss: 2,
                bw_mhz: 80,
                sgi: true,
            },
            TxRate::Vht {
                mcs: 9,
                nss: 2,
                bw_mhz: 80,
                sgi: false,
            },
            TxRate::Vht {
                mcs: 5,
                nss: 1,
                bw_mhz: 40,
                sgi: true,
            },
        ] {
            for no_ack in [false, true] {
                let mut buf = Vec::new();
                write_tx_radiotap(&mut buf, rate, no_ack);
                assert_eq!(buf, radiotap::tx_header(rate, no_ack));
            }
        }
    }

    fn build_ipv6_tcp_packet(
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        options: &[u8],
        payload: &[u8],
    ) -> Ipv6Packet {
        assert_eq!(options.len() % 4, 0);
        let tcp_hdr_len = 20 + options.len();
        let tcp_len = tcp_hdr_len + payload.len();
        let mut buf = vec![0u8; 40 + tcp_len];
        // IPv6 header
        buf[0] = 0x60;
        buf[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
        buf[6] = IPPROTO_TCP;
        buf[7] = 64;
        buf[8..24].copy_from_slice(&src_ip);
        buf[24..40].copy_from_slice(&dst_ip);
        // TCP header
        buf[40..42].copy_from_slice(&src_port.to_be_bytes());
        buf[42..44].copy_from_slice(&dst_port.to_be_bytes());
        buf[44..48].copy_from_slice(&seq.to_be_bytes());
        buf[48..52].copy_from_slice(&ack.to_be_bytes());
        buf[52] = ((tcp_hdr_len / 4) as u8) << 4;
        buf[53] = flags;
        buf[54..56].copy_from_slice(&window.to_be_bytes());
        buf[60..60 + options.len()].copy_from_slice(options);
        buf[60 + options.len()..].copy_from_slice(payload);
        let csum = compute_ipv6_tcp_checksum(&buf);
        buf[56..58].copy_from_slice(&csum.to_be_bytes());
        Ipv6Packet::from_ip(buf).expect("valid IPv6 packet")
    }

    fn ts_opt(tsval: u32, tsecr: u32) -> [u8; 12] {
        let mut opt = [0u8; 12];
        opt[0..4].copy_from_slice(&[0x01, 0x01, 0x08, 0x0a]);
        opt[4..8].copy_from_slice(&tsval.to_be_bytes());
        opt[8..12].copy_from_slice(&tsecr.to_be_bytes());
        opt
    }

    fn sample_ips() -> ([u8; 16], [u8; 16]) {
        (
            owly_awdl::MacAddr([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01])
                .link_local()
                .octets(),
            owly_awdl::MacAddr([0x02, 0x79, 0x22, 0x55, 0x6d, 0x0d])
                .link_local()
                .octets(),
        )
    }

    #[test]
    fn gro_coalesces_contiguous_segments_with_valid_checksum() {
        let (src, dst) = sample_ips();
        let mut gro = TcpCoalescer::new(true);
        let t0 = Instant::now();
        let mut out: Vec<Vec<u8>> = Vec::new();

        // 4 contiguous segments including odd payload length and advancing TSval.
        let p1 = b"hello world ";
        let p2 = b"from mt7922 ";
        let p3 = b"software GRO!"; // odd length (13)
        let p4 = b" done.";
        let payloads: [&[u8]; 4] = [p1, p2, p3, p4];
        let mut seq = 1000u32;
        for (i, payload) in payloads.iter().enumerate() {
            let opt = ts_opt(5000 + i as u32, 9999);
            let pkt = build_ipv6_tcp_packet(
                src, dst, 50000, 8771, seq, 42, TCP_ACK, 4096, &opt, payload,
            );
            seq = seq.wrapping_add(payload.len() as u32);
            gro.offer(pkt, t0, |raw| {
                out.push(raw.to_vec());
                true
            });
        }
        assert!(out.is_empty(), "batch should stay buffered until flush");
        gro.flush(|raw| {
            out.push(raw.to_vec());
            true
        });

        assert_eq!(out.len(), 1);
        let merged = &out[0];
        let expected_payload: Vec<u8> = payloads.iter().flat_map(|p| p.iter().copied()).collect();
        assert_eq!(merged.len(), 72 + expected_payload.len());
        assert_eq!(
            u16::from_be_bytes([merged[4], merged[5]]) as usize,
            merged.len() - 40
        );
        // Starting seq preserved from first segment.
        assert_eq!(u32::from_be_bytes([merged[44], merged[45], merged[46], merged[47]]), 1000);
        // Latest TSval preserved from last segment.
        assert_eq!(u32::from_be_bytes([merged[64], merged[65], merged[66], merged[67]]), 5003);
        assert_eq!(&merged[72..], expected_payload.as_slice());
        // Valid IPv6 TCP checksum.
        let wire_csum = u16::from_be_bytes([merged[56], merged[57]]);
        assert_eq!(compute_ipv6_tcp_checksum(merged), wire_csum);
    }

    #[test]
    fn gro_flushes_on_seq_gap() {
        let (src, dst) = sample_ips();
        let mut gro = TcpCoalescer::new(true);
        let t0 = Instant::now();
        let mut out: Vec<Vec<u8>> = Vec::new();

        let pkt1 = build_ipv6_tcp_packet(src, dst, 1234, 8771, 100, 1, TCP_ACK, 2048, &[], b"aaaa");
        let pkt2 = build_ipv6_tcp_packet(src, dst, 1234, 8771, 104, 1, TCP_ACK, 2048, &[], b"bbbb");
        // Gap: jumps from 108 to 200.
        let pkt3 = build_ipv6_tcp_packet(src, dst, 1234, 8771, 200, 1, TCP_ACK, 2048, &[], b"cccc");

        gro.offer(pkt1, t0, |raw| { out.push(raw.to_vec()); true });
        gro.offer(pkt2, t0, |raw| { out.push(raw.to_vec()); true });
        assert!(out.is_empty());
        gro.offer(pkt3, t0, |raw| { out.push(raw.to_vec()); true });
        // pkt1+pkt2 flushed on gap; pkt3 still buffered.
        assert_eq!(out.len(), 1);
        assert_eq!(&out[0][60..], b"aaaabbbb");
        gro.flush(|raw| { out.push(raw.to_vec()); true });
        assert_eq!(out.len(), 2);
        assert_eq!(&out[1][60..], b"cccc");
    }

    #[test]
    fn gro_bypasses_syn_fin_rst_and_pure_ack_in_order() {
        let (src, dst) = sample_ips();
        let mut gro = TcpCoalescer::new(true);
        let t0 = Instant::now();
        let mut out: Vec<Vec<u8>> = Vec::new();

        // Buffer one data segment first, then send SYN, FIN, RST, pure-ACK.
        let data = build_ipv6_tcp_packet(src, dst, 1234, 8771, 10, 1, TCP_ACK, 2048, &[], b"xy");
        let pure_ack = build_ipv6_tcp_packet(src, dst, 1234, 8771, 12, 1, TCP_ACK, 2048, &[], b"");
        let syn = build_ipv6_tcp_packet(src, dst, 1234, 8771, 12, 0, 0x02, 2048, &[], b"");
        let fin = build_ipv6_tcp_packet(src, dst, 1234, 8771, 12, 1, TCP_ACK | 0x01, 2048, &[], b"z");
        let rst = build_ipv6_tcp_packet(src, dst, 1234, 8771, 13, 1, TCP_ACK | 0x04, 2048, &[], b"");

        gro.offer(data, t0, |raw| { out.push(raw.to_vec()); true });
        assert!(out.is_empty());
        gro.offer(pure_ack, t0, |raw| { out.push(raw.to_vec()); true });
        // Pending data flushed before pure ACK, preserving order.
        assert_eq!(out.len(), 2);
        assert_eq!(&out[0][60..], b"xy");
        assert_eq!(out[1].len(), 60);

        for ctrl in [syn, fin, rst] {
            let before = out.len();
            gro.offer(ctrl, t0, |raw| { out.push(raw.to_vec()); true });
            assert_eq!(out.len(), before + 1);
        }
    }

    #[test]
    fn gro_flushes_immediately_on_psh_and_preserves_flag() {
        let (src, dst) = sample_ips();
        let mut gro = TcpCoalescer::new(true);
        let t0 = Instant::now();
        let mut out: Vec<Vec<u8>> = Vec::new();

        let p1 = build_ipv6_tcp_packet(src, dst, 4444, 8771, 500, 7, TCP_ACK, 8192, &[], b"part1");
        let p2 = build_ipv6_tcp_packet(
            src, dst, 4444, 8771, 505, 7, TCP_ACK | TCP_PSH, 8192, &[], b"part2",
        );
        gro.offer(p1, t0, |raw| { out.push(raw.to_vec()); true });
        assert!(out.is_empty());
        gro.offer(p2, t0, |raw| { out.push(raw.to_vec()); true });
        assert_eq!(out.len(), 1);
        assert_eq!(out[0][53], TCP_ACK | TCP_PSH);
        assert_eq!(&out[0][60..], b"part1part2");
        assert_eq!(
            compute_ipv6_tcp_checksum(&out[0]),
            u16::from_be_bytes([out[0][56], out[0][57]])
        );
    }

    #[test]
    fn gro_flushes_at_max_16_segments() {
        let (src, dst) = sample_ips();
        let mut gro = TcpCoalescer::new(true);
        let t0 = Instant::now();
        let mut out: Vec<Vec<u8>> = Vec::new();

        let chunk = [0x5au8; 100];
        for i in 0..17u32 {
            let pkt = build_ipv6_tcp_packet(
                src, dst, 5555, 8771, i * 100, 1, TCP_ACK, 4096, &[], &chunk,
            );
            gro.offer(pkt, t0, |raw| { out.push(raw.to_vec()); true });
        }
        // First 16 flushed automatically on the 16th segment; 17th remains buffered.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].len(), 60 + 16 * 100);
        gro.flush(|raw| { out.push(raw.to_vec()); true });
        assert_eq!(out.len(), 2);
        assert_eq!(out[1].len(), 60 + 100);

        // Also verify ~24 KiB merged size cap flushes before exceeding GRO_MAX_BYTES.
        out.clear();
        let big = vec![0x33u8; 3000];
        for i in 0..9u32 {
            let pkt = build_ipv6_tcp_packet(
                src, dst, 5556, 8771, i * 3000, 1, TCP_ACK, 4096, &[], &big,
            );
            gro.offer(pkt, t0, |raw| { out.push(raw.to_vec()); true });
        }
        // 8 * 3000 + 60 = 24060 <= 24576; 9th would exceed 24576, flushing the first 8.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].len(), 60 + 8 * 3000);
        gro.flush(|raw| { out.push(raw.to_vec()); true });
        assert_eq!(out.len(), 2);
        assert_eq!(out[1].len(), 60 + 3000);
    }

    #[test]
    fn gro_passes_through_non_tcp_udp_and_icmpv6() {
        let (src, dst) = sample_ips();
        let mut gro = TcpCoalescer::new(true);
        let t0 = Instant::now();
        let mut out: Vec<Vec<u8>> = Vec::new();

        let make_other = |next_hdr: u8, payload: &[u8]| {
            let mut buf = vec![0u8; 40 + payload.len()];
            buf[0] = 0x60;
            buf[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
            buf[6] = next_hdr;
            buf[7] = 64;
            buf[8..24].copy_from_slice(&src);
            buf[24..40].copy_from_slice(&dst);
            buf[40..].copy_from_slice(payload);
            Ipv6Packet::from_ip(buf).unwrap()
        };

        let tcp1 = build_ipv6_tcp_packet(src, dst, 1000, 8771, 1, 1, TCP_ACK, 1024, &[], b"abc");
        let udp = make_other(17, b"mdns-udp-payload");
        let icmpv6 = make_other(58, b"icmpv6-echo");

        gro.offer(tcp1, t0, |raw| { out.push(raw.to_vec()); true });
        gro.offer(udp.clone(), t0, |raw| { out.push(raw.to_vec()); true });
        gro.offer(icmpv6.clone(), t0, |raw| { out.push(raw.to_vec()); true });
        assert_eq!(out.len(), 3);
        assert_eq!(&out[0][60..], b"abc");
        assert_eq!(out[1], udp.data);
        assert_eq!(out[2], icmpv6.data);
    }

    #[test]
    fn gro_flushes_on_hold_timeout_and_falls_back_on_alloc_failure() {
        let (src, dst) = sample_ips();
        let mut gro = TcpCoalescer::new(true);
        let t0 = Instant::now();
        let mut out: Vec<Vec<u8>> = Vec::new();

        // 1. Hold timeout (> 500 us) flushes stale batch before starting new one.
        let p1 = build_ipv6_tcp_packet(src, dst, 2222, 8771, 10, 1, TCP_ACK, 4096, &[], b"old");
        let p2 = build_ipv6_tcp_packet(src, dst, 2222, 8771, 13, 1, TCP_ACK, 4096, &[], b"new");
        gro.offer(p1, t0, |raw| { out.push(raw.to_vec()); true });
        gro.offer(p2, t0 + Duration::from_micros(600), |raw| {
            out.push(raw.to_vec());
            true
        });
        assert_eq!(out.len(), 1);
        assert_eq!(&out[0][60..], b"old");
        gro.flush(|raw| { out.push(raw.to_vec()); true });
        assert_eq!(out.len(), 2);
        assert_eq!(&out[1][60..], b"new");

        // 2. Fallback when WintunAllocateSendPacket rejects the coalesced packet.
        out.clear();
        let q1 = build_ipv6_tcp_packet(src, dst, 3333, 8771, 100, 1, TCP_ACK, 4096, &[], b"1111");
        let q2 = build_ipv6_tcp_packet(
            src, dst, 3333, 8771, 104, 1, TCP_ACK | TCP_PSH, 4096, &[], b"2222",
        );
        gro.offer(q1.clone(), t0, |raw| { out.push(raw.to_vec()); true });
        gro.offer(q2.clone(), t0, |raw| {
            if raw.len() > 64 {
                return false; // Simulate WintunAllocateSendPacket failure on merged packet.
            }
            out.push(raw.to_vec());
            true
        });
        assert_eq!(gro.fallbacks, 1);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], q1.data);
        assert_eq!(out[1], q2.data);
    }

    #[test]
    fn gro_bypasses_corrupted_checksum_and_respects_disabled_mode() {
        let (src, dst) = sample_ips();
        let t0 = Instant::now();
        let mut out: Vec<Vec<u8>> = Vec::new();

        // Corrupted checksum segment must bypass GRO so Windows drops it cleanly.
        let mut gro = TcpCoalescer::new(true);
        let good = build_ipv6_tcp_packet(src, dst, 7777, 8771, 1, 1, TCP_ACK, 4096, &[], b"ok");
        let mut bad = build_ipv6_tcp_packet(src, dst, 7777, 8771, 3, 1, TCP_ACK, 4096, &[], b"no");
        bad.data[56] ^= 0xff; // corrupt checksum
        gro.offer(good, t0, |raw| { out.push(raw.to_vec()); true });
        gro.offer(bad.clone(), t0, |raw| { out.push(raw.to_vec()); true });
        assert_eq!(out.len(), 2);
        assert_eq!(out[1], bad.data);

        // Disabled mode emits every segment immediately without coalescing.
        out.clear();
        let mut gro_off = TcpCoalescer::new(false);
        let a = build_ipv6_tcp_packet(src, dst, 7777, 8771, 10, 1, TCP_ACK, 4096, &[], b"aa");
        let b = build_ipv6_tcp_packet(src, dst, 7777, 8771, 12, 1, TCP_ACK, 4096, &[], b"bb");
        gro_off.offer(a, t0, |raw| { out.push(raw.to_vec()); true });
        gro_off.offer(b, t0, |raw| { out.push(raw.to_vec()); true });
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn rx_bridge_buffers_overflow_without_dropping_frames() {
        let (tx, mut rx) = mpsc::channel::<Received>(2);
        let mut bridge = RxBridge::new(tx);
        for i in 0..5u8 {
            bridge.push(Received {
                bytes: vec![i; 20],
                rssi: Some(-40),
            });
        }
        assert_eq!(bridge.overflow.len(), 3);
        assert_eq!(bridge.dropped, 0);

        // Drain channel and flush overflow; all 5 frames arrive in exact order.
        let mut got = Vec::new();
        while got.len() < 5 {
            if let Ok(frame) = rx.try_recv() {
                got.push(frame.bytes[0]);
            }
            bridge.drain();
        }
        assert_eq!(got, vec![0, 1, 2, 3, 4]);
        assert!(bridge.overflow.is_empty());
    }

    #[test]
    fn direct_mtk_rx_cb_preserves_12kib_rx_amsdu_without_truncation() {
        let (tx, mut rx) = mpsc::channel::<Received>(4);
        let mut bridge = RxBridge::new(tx);
        let payload: Vec<u8> = (0..12_288).map(|i| (i & 0xff) as u8).collect();
        let ctx = (&mut bridge as *mut RxBridge) as *mut c_void;
        #[allow(unsafe_code)]
        unsafe {
            direct_mtk_rx_cb(payload.as_ptr(), payload.len(), -35, ctx);
        }
        bridge.drain();
        let received = rx.try_recv().expect("12 KiB RX A-MSDU delivered");
        assert_eq!(received.bytes.len(), 12_288);
        assert_eq!(received.bytes, payload);
        assert_eq!(received.rssi, Some(-35));
    }
}

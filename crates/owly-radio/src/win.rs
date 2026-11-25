//! owly-awdl on Windows: its [`driver`] over a user-space radio daemon's
//! Named Pipe (`\\.\pipe\winawdl-radio`, using the `radio_link.h` framing)
//! and a Layer-3 Wintun adapter (`awdl0`).
//!
//! Its [`Air`] is [`PipeAir`], talking to `mtkradio.exe` over a duplex
//! overlapped Windows Named Pipe. Its [`Netif`] is [`WintunNetif`], a
//! Wintun adapter configured with MTU 1450 and the AWDL MAC's EUI-64
//! IPv6 link-local address without DAD (NET-1).

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

/// `awdl0`'s MTU.
pub const TAP_MTU: u32 = 1450;

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
        let wintun = WintunAdapter::create(tap, link_local)?;
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

impl Air for PipeAir {
    async fn recv(&mut self) -> io::Result<Received> {
        loop {
            let avail = self.rx_end - self.rx_start;
            if avail >= 8 {
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
                if avail >= frame_len {
                    let body_start = self.rx_start + 8;
                    let body_end = self.rx_start + frame_len;
                    self.rx_start = body_end;
                    if self.rx_start == self.rx_end {
                        self.rx_start = 0;
                        self.rx_end = 0;
                    }
                    if msg_type == RADIO_LINK_RX {
                        if let Some(rx) = radiotap::parse(&self.rx_buf[body_start..body_end]) {
                            return Ok(Received {
                                bytes: rx.frame.to_vec(),
                                rssi: rx.rssi,
                            });
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
                    continue;
                }
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

#[allow(unsafe_code)]
unsafe extern "C" fn direct_mtk_rx_cb(
    frame: *const u8,
    len: usize,
    rssi: i8,
    ctx: *mut c_void,
) {
    if frame.is_null() || len < 16 || ctx.is_null() {
        return;
    }
    let tx = unsafe { &*(ctx as *const mpsc::Sender<Received>) };
    let slice = unsafe { std::slice::from_raw_parts(frame, len) };
    let _ = tx.try_send(Received {
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
                let rx_ctx = (&rx_tx as *const mpsc::Sender<Received>) as *mut c_void;
                let mut pending_tx: Option<Frame> = None;

                while !stop_bg.load(Ordering::Relaxed) {
                    let mut tx_sent = 0usize;
                    for _ in 0..256 {
                        let frame = match pending_tx.take() {
                            Some(f) => f,
                            None => match tx_rx.try_recv() {
                                Ok(f) => f,
                                Err(_) => break,
                            },
                        };
                        let (rate_mode, rate_val, nss, bw, sgi) = match frame.rate {
                            TxRate::Legacy(r) => (0u8, (r / 2).max(6), 1u8, 0u8, 0u8),
                            TxRate::Ht { mcs, sgi } => {
                                (1u8, mcs, 1u8, 0u8, if sgi { 1 } else { 0 })
                            }
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
                        };
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
                                if frame.no_ack { 1 } else { 0 },
                                0, // batch kick below
                            )
                        };
                        if ok != 0 {
                            tx_sent += 1;
                        } else {
                            // Hardware TX DMA ring (256 slots) momentarily full: kick & retry next turn.
                            pending_tx = Some(frame);
                            break;
                        }
                    }
                    if tx_sent > 0 {
                        #[allow(unsafe_code)]
                        unsafe {
                            (dll.kick_tx)(handle);
                        }
                    }

                    #[allow(unsafe_code)]
                    let rx_got = unsafe { (dll.poll)(handle, Some(direct_mtk_rx_cb), rx_ctx) };

                    if pending_tx.is_some() {
                        thread::yield_now();
                    } else if tx_sent > 0 || rx_got > 0 {
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
    fn create(name: &str, link_local: Ipv6Addr) -> io::Result<Self> {
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

        if let Err(e) = configure_ipv6_interface(luid, link_local) {
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

fn configure_ipv6_interface(luid: NET_LUID_LH, link_local: Ipv6Addr) -> io::Result<()> {
    // 1. Set MTU = 1450 and disable DAD on IPv6.
    #[allow(unsafe_code)]
    // SAFETY: `MIB_IPINTERFACE_ROW` is a plain C struct initialized before `GetIpInterfaceEntry`.
    let mut iface_row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    iface_row.Family = AF_INET6;
    iface_row.InterfaceLuid = luid;
    #[allow(unsafe_code)]
    // SAFETY: `iface_row` has `Family` and `InterfaceLuid` set.
    let err = unsafe { GetIpInterfaceEntry(&mut iface_row) };
    if err == NO_ERROR {
        iface_row.NlMtu = TAP_MTU;
        iface_row.DadTransmits = 0;
        iface_row.SitePrefixLength = 0;
        #[allow(unsafe_code)]
        // SAFETY: `iface_row` was populated by `GetIpInterfaceEntry`.
        let set_err = unsafe { SetIpInterfaceEntry(&mut iface_row) };
        if set_err != NO_ERROR {
            tracing::warn!("SetIpInterfaceEntry(MTU={TAP_MTU}) returned error {set_err}");
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

struct WintunNetif {
    dll: Arc<WintunDll>,
    adapter: SendHandle,
    session: SendHandle,
    stop_event: SendHandle,
    rx: Option<mpsc::Receiver<Ipv6Packet>>,
    rx_thread: Option<JoinHandle<()>>,
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

        Ok(Self {
            dll,
            adapter,
            session: session_h,
            stop_event: stop_h,
            rx: Some(rx),
            rx_thread: Some(rx_thread),
        })
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

    fn deliver(&mut self, packet: Ipv6Packet) {
        let len = packet.data.len();
        if len == 0 || len > u32::MAX as usize {
            return;
        }
        #[allow(unsafe_code)]
        // SAFETY: `self.session.0` is valid for the lifetime of `WintunNetif`.
        unsafe {
            let dst = (self.dll.allocate_send_packet)(self.session.0, len as u32);
            if !dst.is_null() {
                ptr::copy_nonoverlapping(packet.data.as_ptr(), dst, len);
                (self.dll.send_packet)(self.session.0, dst);
            }
        }
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
}

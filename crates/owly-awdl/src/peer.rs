//! The peer table's entries: what each AWDL peer has said about itself.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ba_reorder::{BA_REORDER_TIDS, BaReorder};
use crate::channel::Sequence;
use crate::election::Election;
use crate::frame::Header;
use crate::tlv::{Advert, HtCapabilities, VhtCapabilities};
use crate::{MacAddr, Time};

/// A buffered QoS Data frame held inside a peer's RX Block Ack reorder buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeldData {
    pub header: Header,
    pub amsdu: bool,
    pub body: Vec<u8>,
}

/// An AWDL peer, as heard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub mac: MacAddr,
    /// From its ARPA TLV.
    pub name: String,
    pub version: u8,
    pub devclass: u8,
    /// Of the last action frame heard from it, in dBm.
    pub rssi: Option<i8>,
    /// When it was last heard, by action or data frame.
    pub last_seen: Time,
    pub election: Election,
    pub sequence: Option<Sequence>,
    /// How far its AW schedule is ahead of ours, in µs.
    pub sync_offset_us: Option<i64>,
    pub ht: Option<HtCapabilities>,
    pub vht: Option<VhtCapabilities>,
    /// Whether the peer advertised Apple AWDL Wi-Fi 6 (HE) support in TLV 12.
    pub he: bool,
    /// Its station address on its infrastructure network.
    pub infra: Option<MacAddr>,
    /// Whether it has sent a MIF.
    pub mif: bool,
    /// Whether it sends Election Parameters version 2, which then wins
    /// over version 1.
    pub v2: bool,
    /// It has sent a MIF and announced its version and device class: only
    /// then is it a peer to talk to (AWDL-17).
    pub valid: bool,
    /// Whether this peer has accepted our TX Block Ack (TID 0) session.
    pub(crate) tx_ba_active: bool,
    /// When we last sent an ADDBA Request to this peer.
    pub(crate) tx_ba_last_req: Option<Time>,
    /// Next ADDBA Request dialog token for this peer.
    pub(crate) tx_ba_token: u8,
    /// Active 802.11 RX Block Ack reorder buffers indexed by QoS TID (`0..8`).
    pub(crate) rx_ba: [Option<BaReorder<HeldData>>; BA_REORDER_TIDS],
}

/// What a host is told about a peer that has turned valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    pub mac: MacAddr,
    pub name: String,
    pub devclass: u8,
    pub rssi: Option<i8>,
}

impl Peer {
    pub fn new(mac: MacAddr, now: Time) -> Peer {
        Peer {
            mac,
            name: String::new(),
            version: 0,
            devclass: 0,
            rssi: None,
            last_seen: now,
            election: Election::own(mac),
            sequence: None,
            sync_offset_us: None,
            ht: None,
            vht: None,
            he: false,
            infra: None,
            mif: false,
            v2: false,
            valid: false,
            tx_ba_active: false,
            tx_ba_last_req: None,
            tx_ba_token: 0,
            rx_ba: [const { None }; BA_REORDER_TIDS],
        }
    }

    pub fn info(&self) -> PeerInfo {
        PeerInfo {
            mac: self.mac,
            name: self.name.clone(),
            devclass: self.devclass,
            rssi: self.rssi,
        }
    }

    /// Takes in what one of its action frames said, except its sync
    /// parameters, which the node reads against its own clock. Returns
    /// whether it has just turned valid.
    pub(crate) fn absorb(&mut self, a: &Advert, mif: bool) -> bool {
        if let Some(name) = &a.name {
            self.name.clone_from(name);
        }
        if let Some((version, devclass)) = a.version {
            self.version = version;
            self.devclass = devclass;
        }
        if let Some(s) = a.sequence {
            self.sequence = Some(s);
        }
        if let Some(ht) = a.ht {
            self.ht = Some(ht);
        }
        if let Some(vht) = a.vht {
            self.vht = Some(vht);
        }
        if let Some(dp) = a.data_path {
            if let Some(infra) = dp.infra {
                self.infra = Some(infra);
            }
            self.he = dp.he;
        }
        if let Some(e) = a.election
            && (a.election_v2 || !self.v2)
        {
            let el = &mut self.election;
            el.master = e.master;
            el.height = e.height;
            el.master_metric = e.master_metric;
            el.self_metric = e.self_metric;
            if a.election_v2 {
                el.sync = e.sync.unwrap_or(self.mac);
                el.master_counter = e.master_counter;
                el.self_counter = e.self_counter;
                self.v2 = true;
            }
        }
        self.mif |= mif;
        let was = self.valid;
        self.valid = self.mif && self.version != 0 && self.devclass != 0;
        self.valid && !was
    }
}

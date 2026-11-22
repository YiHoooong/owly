//! The radio on Linux: the Backend trait and its injection backend, capability probing and quirks, and owly-awdl over nl80211.
//!
//! [`radio`] is the [`Backend`](radio::Backend) trait owlyd runs, and the
//! link a backend brings up. [`injection`] implements it with owly-awdl ([`native`]), on interfaces it sets up through [`nl80211`] and [`rtnl`], in the mode each
//! card needs: shared, exclusive (an ad-hoc cell or hidden AP) or active
//! monitor. It picks the mode from what [`probe`] finds and what [`quirks`]
//! records, and writes each change to a recovery [`journal`] before making
//! it, with the settings [`config`] reads from `/etc/owly/radio.toml`.
//! [`fake`] is a backend for testing what runs on top.

#[cfg(target_os = "linux")]
pub mod capture;
#[cfg(target_os = "linux")]
pub mod config;
#[cfg(target_os = "linux")]
pub mod fake;
#[cfg(target_os = "linux")]
pub mod injection;
#[cfg(target_os = "linux")]
pub mod journal;
#[cfg(target_os = "linux")]
pub mod native;
#[cfg(windows)]
#[path = "win.rs"]
pub mod native;
#[cfg(target_os = "linux")]
pub mod netlink;
#[cfg(target_os = "linux")]
pub mod nl80211;
pub mod pcap;
#[cfg(target_os = "linux")]
pub mod probe;
#[cfg(target_os = "linux")]
pub mod quirks;
#[cfg(target_os = "linux")]
pub mod radio;
pub mod radiotap;
#[cfg(target_os = "linux")]
pub mod rtnl;
#[cfg(target_os = "linux")]
pub mod rundir;
#[cfg(target_os = "linux")]
pub mod sys;

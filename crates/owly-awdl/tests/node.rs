//! `Node` against frames crafted as an iPhone sends them: what it takes a
//! peer for, what it advertises (AWDL-12), when it sends (AWDL-16), and
//! what it hands the IP stack.

use owly_awdl::channel::{Encoding, SLOTS};
use owly_awdl::election::Election;
use owly_awdl::frame::{self, subtype};
use owly_awdl::sync::{SLOT_US, UNICAST_GUARD_US};
use owly_awdl::tlv::{self, HtCapabilities, Own};
use owly_awdl::{
    Action, Channel, Config, Input, Ipv6Packet, MacAddr, Node, Presence, RadioConstraints,
    Sequence, TU, Time,
};

const US: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x01]);
const PHONE: MacAddr = MacAddr([0x86, 0x08, 0x04, 0x8a, 0x2b, 0xf4]);
const START: Time = Time(10_000_000);

fn node(channel: u8, presence: Presence) -> Node {
    let radio = RadioConstraints {
        channel: Channel(channel),
        presence,
    };
    Node::new(Config::new(US, "owly", radio), START)
}

fn seq(channels: [u8; SLOTS]) -> Sequence {
    let mut s = Sequence::empty(Encoding::OpClass);
    for (slot, c) in s.slots.iter_mut().zip(channels) {
        if c != 0 {
            *slot = Channel(c).slot();
        }
    }
    s
}

/// An iPhone's action frame: master of its own tree with metric 600, at the
/// start of its AW `aw_counter`'s slot.
fn phone_frame(kind: u8, sequence: &Sequence, aw_counter: u16, next_tu: u16) -> Vec<u8> {
    frame_from(PHONE, kind, sequence, aw_counter, next_tu)
}

/// The same frame from any address.
fn frame_from(
    mac: MacAddr,
    kind: u8,
    sequence: &Sequence,
    aw_counter: u16,
    next_tu: u16,
) -> Vec<u8> {
    let mut e = Election::own(mac);
    e.self_metric = 600;
    e.master_metric = 600;
    let own = Own {
        addr: mac,
        name: "iPhone",
        devclass: tlv::devclass::IOS,
        channel: sequence.channel(0),
        master_channel: Channel(149),
        next_tu,
        aw_counter,
        psf_interval_tu: 110,
        sequence,
        election: &e,
        ht: Some(HtCapabilities::ONE_STREAM),
        vht: None,
        he: true,
    };
    frame::action_frame(mac, 1, kind, 0, |out| {
        tlv::put_all(out, &own, kind == subtype::MIF)
    })
}

fn feed(n: &mut Node, at: Time, bytes: &[u8]) -> Vec<Action> {
    n.handle(Input::Frame {
        rx_time: at,
        rssi: Some(-40),
        bytes,
    })
    .collect()
}

fn tick(n: &mut Node, at: Time) -> Vec<Action> {
    n.handle(Input::Timer(at)).collect()
}

/// Has the phone become our master: a MIF, then the election's tick.
fn meet(n: &mut Node, sequence: &Sequence) -> Time {
    let t = START.plus(100_000);
    let a = feed(n, t, &phone_frame(subtype::MIF, sequence, 400, 64));
    assert!(
        a.iter()
            .any(|a| matches!(a, Action::PeerUp(p) if p.mac == PHONE))
    );
    let t = START.plus(1_000_000);
    // Heard again just before the tick, so its phase is current.
    feed(n, t, &phone_frame(subtype::PSF, sequence, 400 + 4 * 14, 64));
    tick(n, t);
    assert_eq!(n.election().sync, PHONE);
    t
}

fn tcp_syn() -> Ipv6Packet {
    let mut seg = vec![0u8; 20];
    seg[12] = 5 << 4;
    seg[13] = 0x02;
    let mut data = vec![0x60, 0, 0, 0, 0, 20, 6, 64];
    data.extend(PHONE.link_local().octets());
    data.extend(US.link_local().octets());
    data.extend(seg);
    Ipv6Packet {
        dst: US,
        src: PHONE,
        data,
    }
}

fn data_from_phone(p: &Ipv6Packet) -> Vec<u8> {
    frame::data_frame(PHONE, p.dst, 9, 9, &p.data)
}

fn transmits(actions: &[Action]) -> Vec<&frame::Frame> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Transmit { frame, .. } => Some(frame),
            _ => None,
        })
        .collect()
}

const PHONE_SEQ: [u8; SLOTS] = [149, 149, 149, 0, 0, 0, 0, 0, 6, 149, 149, 0, 0, 0, 0, 0];

// spec: AWDL-12
#[test]
fn a_fixed_radio_advertises_its_channel_in_every_slot() {
    let mut n = node(6, Presence::Fixed);
    meet(&mut n, &seq(PHONE_SEQ));
    assert_eq!(n.sequence().channels(), [6; SLOTS]);
}

// spec: AWDL-12
#[test]
fn a_shared_radio_advertises_only_the_masters_slots_on_its_channel() {
    let mut n = node(6, Presence::Share);
    meet(&mut n, &seq(PHONE_SEQ));
    let mut want = [0; SLOTS];
    want[8] = 6;
    assert_eq!(n.sequence().channels(), want);
    assert_eq!(n.no_overlap(), None);
    // A master with no slot on our channel: what we had stands, and the
    // host hears which channel the master is on instead.
    let mut n = node(44, Presence::Share);
    meet(&mut n, &seq(PHONE_SEQ));
    assert_eq!(n.sequence().channels(), [44; SLOTS]);
    assert!(n.stats().no_overlap > 0);
    assert_eq!(n.no_overlap(), Some((PHONE, 149)));
}

// spec: AWDL-17
#[test]
fn a_peer_is_valid_once_it_has_sent_a_mif_with_its_version() {
    let mut n = node(6, Presence::Fixed);
    let s = seq(PHONE_SEQ);
    let a = feed(&mut n, START, &phone_frame(subtype::PSF, &s, 400, 64));
    assert!(!a.iter().any(|a| matches!(a, Action::PeerUp(_))));
    assert!(!n.peer(PHONE).unwrap().valid);
    let a = feed(
        &mut n,
        START.plus(1000),
        &phone_frame(subtype::MIF, &s, 400, 63),
    );
    let up: Vec<_> = a
        .iter()
        .filter(|a| matches!(a, Action::PeerUp(_)))
        .collect();
    assert_eq!(up.len(), 1);
    let Action::PeerUp(info) = up[0] else {
        unreachable!()
    };
    assert_eq!(
        (info.mac, info.name.as_str(), info.devclass, info.rssi),
        (PHONE, "iPhone", 2, Some(-40))
    );
    // Only once.
    let a = feed(
        &mut n,
        START.plus(2000),
        &phone_frame(subtype::MIF, &s, 400, 62),
    );
    assert!(!a.iter().any(|a| matches!(a, Action::PeerUp(_))));
}

// spec: SEC-11
#[test]
fn spoofed_peers_cannot_fill_the_table() {
    let mut n = node(6, Presence::Fixed);
    let s = seq(PHONE_SEQ);
    let fake = |i: usize| MacAddr([0x02, 0xff, 0, 0, (i >> 8) as u8, i as u8]);
    for i in 0..owly_awdl::MAX_PEERS {
        let at = START.plus(i as u64 * 1000);
        feed(&mut n, at, &frame_from(fake(i), subtype::MIF, &s, 400, 64));
    }
    // The phone takes the place of the fake heard from longest ago.
    let at = START.plus(owly_awdl::MAX_PEERS as u64 * 1000);
    let a = feed(&mut n, at, &phone_frame(subtype::MIF, &s, 400, 64));
    assert!(
        a.iter()
            .any(|a| matches!(a, Action::PeerDown(m) if *m == fake(0)))
    );
    assert!(
        a.iter()
            .any(|a| matches!(a, Action::PeerUp(p) if p.mac == PHONE))
    );
    assert!(n.peer(fake(0)).is_none());
    assert!(n.peer(fake(1)).is_some());
    assert_eq!(n.stats().peers_evicted, 1);
}

// spec: AWDL-18
#[test]
fn a_syn_before_the_mif_is_held_until_the_peer_is_valid() {
    let mut n = node(6, Presence::Fixed);
    let s = seq(PHONE_SEQ);
    feed(&mut n, START, &phone_frame(subtype::PSF, &s, 400, 64));
    let syn = tcp_syn();
    let a = feed(&mut n, START.plus(10), &data_from_phone(&syn));
    assert!(!a.iter().any(|a| matches!(a, Action::Deliver(_))), "{a:?}");
    // Even from a peer we've never heard.
    let a = feed(&mut n, START.plus(20), &data_from_phone(&syn));
    assert!(!a.iter().any(|a| matches!(a, Action::Deliver(_))));
    let a = feed(
        &mut n,
        START.plus(30),
        &phone_frame(subtype::MIF, &s, 400, 63),
    );
    let up = a
        .iter()
        .position(|a| matches!(a, Action::PeerUp(_)))
        .expect("up");
    let delivered: Vec<usize> = a
        .iter()
        .enumerate()
        .filter(|(_, a)| matches!(a, Action::Deliver(p) if *p == syn))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(delivered.len(), 1, "the duplicate is held once");
    assert!(up < delivered[0], "the neighbour entry comes first");
}

// spec: AWDL-18
#[test]
fn held_syns_expire() {
    let mut n = node(6, Presence::Fixed);
    feed(&mut n, START, &data_from_phone(&tcp_syn()));
    tick(&mut n, START.plus(3_000_000));
    let a = feed(
        &mut n,
        START.plus(3_100_000),
        &phone_frame(subtype::MIF, &seq(PHONE_SEQ), 400, 63),
    );
    assert!(!a.iter().any(|a| matches!(a, Action::Deliver(_))));
}

// spec: AWDL-17, NET-3
#[test]
fn data_reaches_the_stack_only_from_peers_and_only_for_us() {
    let mut n = node(6, Presence::Fixed);
    let mut packet = Ipv6Packet::echo_request(PHONE, US, 1, 1, b"hi");
    // From a stranger: dropped.
    assert!(
        !feed(&mut n, START, &data_from_phone(&packet))
            .iter()
            .any(|a| matches!(a, Action::Deliver(_)))
    );
    meet(&mut n, &seq(PHONE_SEQ));
    let t = START.plus(1_100_000);
    let a = feed(&mut n, t, &data_from_phone(&packet));
    assert!(a.contains(&Action::Deliver(packet.clone())));
    // To someone else, which a monitor overhears.
    packet.dst = MacAddr([0x02, 9, 9, 9, 9, 9]);
    assert!(
        !feed(&mut n, t, &data_from_phone(&packet))
            .iter()
            .any(|a| matches!(a, Action::Deliver(_)))
    );
    // To a multicast group.
    packet.dst = MacAddr([0x33, 0x33, 0, 0, 0, 0xfb]);
    assert!(feed(&mut n, t, &data_from_phone(&packet)).contains(&Action::Deliver(packet.clone())));
    // Data keeps the peer alive without action frames (patch owl-07).
    let late = t.plus(4_500_000);
    feed(&mut n, late, &data_from_phone(&packet));
    assert!(
        !tick(&mut n, late.plus(1_000_000))
            .iter()
            .any(|a| matches!(a, Action::PeerDown(_)))
    );
    assert!(tick(&mut n, late.plus(5_100_000)).contains(&Action::PeerDown(PHONE)));
}

#[test]
fn what_the_stack_sends_to_nobody_is_dropped_and_to_us_comes_back() {
    let mut n = node(6, Presence::Fixed);
    let p = Ipv6Packet::echo_request(US, PHONE, 1, 1, b"x");
    let a: Vec<Action> = n
        .handle(Input::Outbound {
            now: START,
            packet: p,
        })
        .collect();
    assert!(transmits(&a).iter().all(|f| f.to != PHONE));
    assert_eq!(n.stats().dropped_no_peer, 1);
    let to_self = Ipv6Packet::echo_request(US, US, 1, 1, b"x");
    let a: Vec<Action> = n
        .handle(Input::Outbound {
            now: START,
            packet: to_self.clone(),
        })
        .collect();
    assert!(a.contains(&Action::Deliver(to_self)));
}

// spec: AWDL-16
#[test]
fn unicast_goes_only_in_shared_slots_clear_of_their_edges() {
    let mut n = node(6, Presence::Share);
    let phone = seq(PHONE_SEQ);
    let mut t = meet(&mut n, &phone);
    let p = Ipv6Packet::echo_request(US, PHONE, 1, 1, b"payload");
    let mut sent_at = None;
    n.handle(Input::Outbound { now: t, packet: p })
        .for_each(drop);
    for _ in 0..(32 * SLOT_US / 256) {
        t = t.plus(256);
        let a = tick(&mut n, t);
        if transmits(&a)
            .iter()
            .any(|f| f.to == PHONE && f.bytes.ends_with(b"payload"))
        {
            sent_at = Some(t);
            break;
        }
    }
    let t = sent_at.expect("never sent");
    let c = n.clock();
    assert_eq!(c.slot(t), 8, "slot 8 is the one both are on 6");
    let into = SLOT_US - c.next_slot_us(t);
    assert!(into >= UNICAST_GUARD_US, "{into} µs into the slot");
}

// spec: AWDL-12, AWDL-16
#[test]
fn a_fixed_radio_sends_unicast_in_every_slot_its_peer_is_on_its_channel_without_acks() {
    let mut phone = PHONE_SEQ;
    phone[3] = 6;
    let mut n = node(6, Presence::Fixed);
    let mut t = meet(&mut n, &seq(phone));
    let mut slots = std::collections::BTreeSet::new();
    for i in 0..6 {
        let p = Ipv6Packet::echo_request(US, PHONE, 1, i, b"payload");
        n.handle(Input::Outbound { now: t, packet: p })
            .for_each(drop);
        let mut sent = false;
        for _ in 0..(32 * SLOT_US / 256) {
            t = t.plus(256);
            let a = tick(&mut n, t);
            let ours = transmits(&a)
                .into_iter()
                .find(|f| f.to == PHONE && f.bytes.ends_with(b"payload"))
                .cloned();
            if let Some(f) = ours {
                assert!(f.no_ack, "patch owl-05: sent once, without an ACK");
                slots.insert(n.clock().slot(t));
                sent = true;
                break;
            }
        }
        assert!(sent, "packet {i} never sent");
        // Into the next slot, so the next packet finds the other one.
        t = t.plus(SLOT_US);
    }
    assert_eq!(slots.into_iter().collect::<Vec<_>>(), [3, 8]);
    // A shared radio waits for ACKs.
    let radio = n.config().radio.clone();
    let shared = RadioConstraints {
        presence: Presence::Share,
        ..radio
    };
    assert!(!Config::new(US, "owly", shared).no_ack);
}

#[test]
fn packets_for_a_peer_that_went_are_dropped_with_it() {
    // On 44, where the phone never is, so nothing goes.
    let mut n = node(44, Presence::Share);
    let t = meet(&mut n, &seq(PHONE_SEQ));
    let queued = t.plus(4_500_000);
    for i in 0..3 {
        let p = Ipv6Packet::echo_request(US, PHONE, 1, i, b"payload");
        n.handle(Input::Outbound {
            now: queued,
            packet: p,
        })
        .for_each(drop);
    }
    // Ours, and the node's own neighbour echoes.
    let queued = n.backlog();
    assert!(queued >= 3, "{queued}");
    // The phone times out with them still young: they go with it, rather
    // than holding up the host until they expire.
    assert!(tick(&mut n, t.plus(5_100_000)).contains(&Action::PeerDown(PHONE)));
    assert_eq!(n.backlog(), 0);
    assert_eq!(n.stats().dropped_no_peer, queued as u64);
    assert_eq!(n.stats().dropped_expired, 0);
    assert_eq!(n.no_overlap(), None, "no master, no overlap to miss");
}

// spec: AWDL-16
#[test]
fn multicast_goes_in_slots_0_and_10_or_any_slot_on_a_fixed_radio() {
    for (presence, slots) in [(Presence::Share, &[0usize, 10][..]), (Presence::Fixed, &[])] {
        let mut n = node(6, presence);
        let mut t = START;
        let group = MacAddr([0x33, 0x33, 0, 0, 0, 0xfb]);
        let mut sent = Vec::new();
        for i in 0..40u64 {
            let mut p = Ipv6Packet::echo_request(US, PHONE, 1, i as u16, b"m");
            p.dst = group;
            n.handle(Input::Outbound { now: t, packet: p })
                .for_each(drop);
            let end = t.plus(SLOT_US);
            while t < end {
                for f in transmits(&tick(&mut n, t)) {
                    if f.to == group {
                        sent.push(n.clock().slot(t));
                    }
                }
                t = t.plus(512);
            }
        }
        assert!(!sent.is_empty());
        if !slots.is_empty() {
            assert!(
                sent.iter().all(|s| slots.contains(s)),
                "{presence:?}: {sent:?}"
            );
        } else {
            let distinct: std::collections::BTreeSet<_> = sent.iter().collect();
            assert!(distinct.len() > 2, "{presence:?}: {sent:?}");
        }
    }
}

#[test]
fn psfs_every_110_tu_and_a_mif_every_slot() {
    let mut n = node(6, Presence::Fixed);
    let mut t = START;
    let (mut psf, mut mif) = (Vec::new(), Vec::new());
    while t < START.plus(1_000_000) {
        let a: Vec<Action> = n.handle(Input::Timer(t)).collect();
        for f in transmits(&a) {
            if let Ok(frame::Received::Action { subtype, .. }) = frame::parse(&f.bytes) {
                if subtype == subtype::PSF {
                    psf.push(t)
                } else {
                    mif.push(t)
                }
            }
        }
        let Some(Action::ArmTimer(next)) = a.last() else {
            panic!("no timer")
        };
        assert!(*next > t);
        t = *next;
    }
    assert_eq!(psf.first(), Some(&START.plus(110 * TU)));
    assert!(psf.windows(2).all(|w| w[1].since(w[0]) == 110 * TU));
    assert!((14..=16).contains(&mif.len()), "{} MIFs", mif.len());
    // The first goes at once, as legacy's did, and the rest mid-slot.
    assert!(
        mif[1..]
            .windows(2)
            .all(|w| w[1].since(w[0]).abs_diff(SLOT_US) < 2 * TU)
    );
}

#[test]
fn weak_frames_are_ignored_and_known_peers_kept_a_little_longer() {
    let mut n = node(6, Presence::Fixed);
    let f = phone_frame(subtype::MIF, &seq(PHONE_SEQ), 400, 64);
    n.handle(Input::Frame {
        rx_time: START,
        rssi: Some(-66),
        bytes: &f,
    })
    .for_each(drop);
    assert!(n.peer(PHONE).is_none());
    n.handle(Input::Frame {
        rx_time: START,
        rssi: Some(-60),
        bytes: &f,
    })
    .for_each(drop);
    n.handle(Input::Frame {
        rx_time: START.plus(1),
        rssi: Some(-69),
        bytes: &f,
    })
    .for_each(drop);
    assert_eq!(n.peer(PHONE).unwrap().rssi, Some(-69));
    n.handle(Input::Frame {
        rx_time: START.plus(2),
        rssi: Some(-71),
        bytes: &f,
    })
    .for_each(drop);
    assert_eq!(n.peer(PHONE).unwrap().rssi, Some(-69));
}

#[test]
fn a_malformed_frame_changes_nothing() {
    let mut n = node(6, Presence::Fixed);
    let mut f = phone_frame(subtype::MIF, &seq(PHONE_SEQ), 400, 64);
    f.push(21); // half a TLV header
    f.push(2);
    feed(&mut n, START, &f);
    assert!(n.peer(PHONE).is_none());
    assert_eq!(n.stats().rx_malformed, 1);
}

// spec: AWDL-15
#[test]
fn block_ack_sessions_are_accepted_only_when_asked_to() {
    let mut req = Vec::new();
    frame::put_header(&mut req, frame::fc::ACTION, US, PHONE, 3);
    req.extend_from_slice(&[3, 0, 9, 0x02, 0x10, 0, 0, 0, 0]);
    for accept in [false, true] {
        let mut n = node(6, Presence::Fixed);
        let mut cfg = n.config().clone();
        cfg.accept_addba = accept;
        n = Node::new(cfg, START);
        meet(&mut n, &seq(PHONE_SEQ));
        let a = feed(&mut n, START.plus(1_200_000), &req);
        let answered = transmits(&a)
            .iter()
            .any(|f| f.to == PHONE && f.bytes[24] == 3 && f.bytes[25] == 1);
        assert_eq!(answered, accept);
    }
}

fn ipv6_tagged(src: MacAddr, dst: MacAddr, tag: u16, payload_len: usize) -> Ipv6Packet {
    assert!(payload_len >= 40 + 8);
    let mut data = vec![0u8; payload_len];
    data[0] = 0x60;
    let body_len = (payload_len - 40) as u16;
    data[4..6].copy_from_slice(&body_len.to_be_bytes());
    data[6] = 6; // TCP
    data[7] = 64;
    data[8..24].copy_from_slice(&src.link_local().octets());
    data[24..40].copy_from_slice(&dst.link_local().octets());
    data[40..42].copy_from_slice(&tag.to_be_bytes());
    Ipv6Packet { dst, src, data }
}

fn delivered_tags(actions: &[Action]) -> Vec<u16> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Deliver(p) if p.data.len() >= 42 && p.data[6] == 6 => {
                Some(u16::from_be_bytes([p.data[40], p.data[41]]))
            }
            _ => None,
        })
        .collect()
}

#[test]
fn node_rx_ba_reorders_out_of_order_qos_and_amsdu_frames() {
    let mut cfg = Config::new(
        US,
        "owly",
        RadioConstraints {
            channel: Channel(149),
            presence: Presence::Fixed,
        },
    );
    cfg.accept_addba = true;
    cfg.neighbour_echo = false;
    assert!(cfg.he, "5 GHz defaults to HE enabled");
    assert_eq!(cfg.mtu, 1500);
    assert_eq!(cfg.max_frame, 3800);

    let mut n = Node::new(cfg, START);
    // Verify our own MIF advertises HE (TLV 12 bit 0x0100) and 2SS VHT80.
    let init = tick(&mut n, START);
    let our_mif = transmits(&init)
        .into_iter()
        .find(|f| f.is_action())
        .expect("MIF sent at start");
    let frame::Received::Action { tlvs, .. } = frame::parse(&our_mif.bytes).unwrap() else {
        panic!("not action");
    };
    let adv = tlv::Advert::parse(tlvs).unwrap();
    assert!(adv.data_path.unwrap().he);
    assert_eq!(adv.vht, Some(tlv::VhtCapabilities::TWO_STREAM_80MHZ));

    let t = meet(&mut n, &seq(PHONE_SEQ));

    // Phone initiates RX BlockAck (TID 0, window 64, SSN = 4094).
    let addba = frame::addba_request(PHONE, US, 1, 7, true, 64, 4094);
    let a = feed(&mut n, t.plus(1000), &addba);
    assert!(
        transmits(&a)
            .iter()
            .any(|f| f.to == PHONE && f.bytes[24] == 3 && f.bytes[25] == 1)
    );

    // Send out-of-order across 4095 -> 0 wrap-around, including a 2-subframe A-MSDU at seq=1.
    let p4094 = ipv6_tagged(PHONE, US, 4094, 80);
    let p4095 = ipv6_tagged(PHONE, US, 4095, 80);
    let p0 = ipv6_tagged(PHONE, US, 0, 80);
    let p1a = ipv6_tagged(PHONE, US, 1001, 80);
    let p1b = ipv6_tagged(PHONE, US, 1002, 80);

    let f1_amsdu = frame::amsdu_frame(PHONE, US, 1, 10, &[&p1a.data, &p1b.data]);
    let f0 = frame::qos_data_frame(PHONE, US, 0, 9, &p0.data);
    let f4095 = frame::qos_data_frame(PHONE, US, 4095, 8, &p4095.data);
    let f4094 = frame::qos_data_frame(PHONE, US, 4094, 7, &p4094.data);

    assert_eq!(delivered_tags(&feed(&mut n, t.plus(2000), &f1_amsdu)), vec![]);
    assert_eq!(delivered_tags(&feed(&mut n, t.plus(2100), &f0)), vec![]);
    assert_eq!(delivered_tags(&feed(&mut n, t.plus(2200), &f4095)), vec![]);
    // Duplicate of buffered seq 1 must be dropped.
    assert_eq!(delivered_tags(&feed(&mut n, t.plus(2300), &f1_amsdu)), vec![]);
    assert_eq!(n.stats().ba_duplicates, 1);

    // Arrival of seq 4094 releases 4094, 4095, 0, and both A-MSDU subframes of 1 in order!
    assert_eq!(
        delivered_tags(&feed(&mut n, t.plus(2400), &f4094)),
        vec![4094, 4095, 0, 1001, 1002]
    );
    // Duplicate of already-delivered seq 4095 is dropped.
    assert_eq!(delivered_tags(&feed(&mut n, t.plus(2500), &f4095)), vec![]);
    assert_eq!(n.stats().ba_duplicates, 2);

    // BAR skips missing seq 2 and releases buffered seq 3.
    let p3 = ipv6_tagged(PHONE, US, 3, 80);
    let f3 = frame::qos_data_frame(PHONE, US, 3, 12, &p3.data);
    assert_eq!(delivered_tags(&feed(&mut n, t.plus(3000), &f3)), vec![]);
    let bar = frame::block_ack_req(PHONE, US, 0, 3);
    assert_eq!(delivered_tags(&feed(&mut n, t.plus(3100), &bar)), vec![3]);

    // Hole timeout flushes buffered seq 5 (seq 4 missing) after BA_REORDER_TIMEOUT_US.
    let p5 = ipv6_tagged(PHONE, US, 5, 80);
    let f5 = frame::qos_data_frame(PHONE, US, 5, 14, &p5.data);
    let held_at = t.plus(4000);
    assert_eq!(delivered_tags(&feed(&mut n, held_at, &f5)), vec![]);
    assert_eq!(
        delivered_tags(&tick(
            &mut n,
            held_at.plus(owly_awdl::ba_reorder::BA_REORDER_TIMEOUT_US - 1)
        )),
        vec![]
    );
    assert_eq!(
        delivered_tags(&tick(
            &mut n,
            held_at.plus(owly_awdl::ba_reorder::BA_REORDER_TIMEOUT_US)
        )),
        vec![5]
    );

    // DELBA flushes buffered seq 7 and tears down the reorder session.
    let p7 = ipv6_tagged(PHONE, US, 7, 80);
    let f7 = frame::qos_data_frame(PHONE, US, 7, 16, &p7.data);
    assert_eq!(delivered_tags(&feed(&mut n, t.plus(100_000), &f7)), vec![]);
    let delba = frame::delba(PHONE, US, 99, 0, true, 39);
    assert_eq!(
        delivered_tags(&feed(&mut n, t.plus(100_100), &delba)),
        vec![7]
    );
    // After DELBA, arbitrary sequence numbers deliver immediately without buffering.
    let p20 = ipv6_tagged(PHONE, US, 20, 80);
    let f20 = frame::qos_data_frame(PHONE, US, 20, 17, &p20.data);
    assert_eq!(
        delivered_tags(&feed(&mut n, t.plus(100_200), &f20)),
        vec![20]
    );
}

#[test]
fn node_tx_packs_two_1500b_packets_into_one_amsdu() {
    let mut cfg = Config::new(
        US,
        "owly",
        RadioConstraints {
            channel: Channel(149),
            presence: Presence::Fixed,
        },
    );
    cfg.amsdu = true;
    cfg.initiate_addba = true;
    cfg.neighbour_echo = false;

    let mut n = Node::new(cfg, START);
    let all_149 = seq([149; SLOTS]);
    let t = meet(&mut n, &all_149);

    // Peer accepts our TX ADDBA Request (status = 0, TID 0, win 64, A-MSDU permitted).
    let mut resp = Vec::new();
    frame::put_header(&mut resp, frame::fc::ACTION, US, PHONE, 5);
    let params: u16 = (64 << 6) | 0x0003;
    resp.extend_from_slice(&[3, 1, 1, 0, 0]);
    resp.extend_from_slice(&params.to_le_bytes());
    resp.extend_from_slice(&[0, 0]);
    feed(&mut n, t.plus(1000), &resp);

    // Send a batch of two 1500-byte IPv6 packets in the middle of a shared slot.
    let send_at = t.plus(SLOT_US / 2);
    let p1 = ipv6_tagged(US, PHONE, 1, 1500);
    let p2 = ipv6_tagged(US, PHONE, 2, 1500);
    let actions: Vec<Action> = n
        .handle(Input::OutboundBatch {
            now: send_at,
            packets: vec![p1.clone(), p2.clone()],
        })
        .collect();
    let data_frames: Vec<&frame::Frame> = transmits(&actions)
        .into_iter()
        .filter(|f| f.to == PHONE && !f.is_action())
        .collect();
    assert_eq!(data_frames.len(), 1, "two 1500B packets packed into 1 A-MSDU");
    assert_eq!(data_frames[0].bytes.len(), 3088);
    assert_eq!(n.stats().tx_amsdu, 1);
    assert_eq!(n.stats().tx_unicast, 2);

    let frame::Received::Data {
        header,
        amsdu,
        body,
    } = frame::parse(&data_frames[0].bytes).unwrap()
    else {
        panic!("not data");
    };
    assert!(amsdu);
    let m = frame::msdus(&header, amsdu, body).unwrap();
    assert_eq!(m.len(), 2);
    assert_eq!(m[0].payload, p1.data.as_slice());
    assert_eq!(m[1].payload, p2.data.as_slice());
}

#[test]
fn node_tx_amsdu_packing_preserves_fifo_order_for_same_peer() {
    let mut cfg = Config::new(
        US,
        "owly",
        RadioConstraints {
            channel: Channel(149),
            presence: Presence::Fixed,
        },
    );
    cfg.amsdu = true;
    cfg.initiate_addba = true;
    cfg.neighbour_echo = false;

    let mut n = Node::new(cfg, START);
    let all_149 = seq([149; SLOTS]);
    let t = meet(&mut n, &all_149);

    // Accept our TX ADDBA Request.
    let mut resp = Vec::new();
    frame::put_header(&mut resp, frame::fc::ACTION, US, PHONE, 5);
    let params: u16 = (64 << 6) | 0x0003;
    resp.extend_from_slice(&[3, 1, 1, 0, 0]);
    resp.extend_from_slice(&params.to_le_bytes());
    resp.extend_from_slice(&[0, 0]);
    feed(&mut n, t.plus(1000), &resp);

    // Queue [1500, 1500, 1500, 100] to the same peer:
    // P3 (1500B) does not fit behind [P1, P2], so P4 (100B) must NOT jump ahead of P3.
    let send_at = t.plus(SLOT_US / 2);
    let p1 = ipv6_tagged(US, PHONE, 1, 1500);
    let p2 = ipv6_tagged(US, PHONE, 2, 1500);
    let p3 = ipv6_tagged(US, PHONE, 3, 1500);
    let p4 = ipv6_tagged(US, PHONE, 4, 100);
    let actions: Vec<Action> = n
        .handle(Input::OutboundBatch {
            now: send_at,
            packets: vec![p1, p2, p3, p4],
        })
        .collect();
    let data_frames: Vec<&frame::Frame> = transmits(&actions)
        .into_iter()
        .filter(|f| f.to == PHONE && !f.is_action())
        .collect();
    assert_eq!(data_frames.len(), 2, "must pack into [P1, P2] then [P3, P4]");

    let mut unpacked_groups = Vec::new();
    for f in data_frames {
        let frame::Received::Data {
            header,
            amsdu,
            body,
        } = frame::parse(&f.bytes).unwrap()
        else {
            panic!("not data");
        };
        assert!(amsdu);
        let tags: Vec<(u16, usize)> = frame::msdus(&header, amsdu, body)
            .unwrap()
            .into_iter()
            .map(|m| {
                let tag = u16::from_be_bytes([m.payload[40], m.payload[41]]);
                (tag, m.payload.len())
            })
            .collect();
        unpacked_groups.push(tags);
    }
    assert_eq!(
        unpacked_groups,
        vec![vec![(1, 1500), (2, 1500)], vec![(3, 1500), (4, 100)]]
    );
}

#[test]
fn node_rx_addba_accepts_amsdu_and_reorders_large_multi_subframe_amsdus() {
    let mut cfg = Config::new(
        US,
        "owly",
        RadioConstraints {
            channel: Channel(149),
            presence: Presence::Fixed,
        },
    );
    assert!(cfg.rx_amsdu, "rx_amsdu defaults to true");
    cfg.accept_addba = true;
    cfg.neighbour_echo = false;

    let mut n = Node::new(cfg.clone(), START);
    let t = meet(&mut n, &seq(PHONE_SEQ));

    // Peer requests RX BA with amsdu=1, win=64, SSN=0.
    let addba = frame::addba_request(PHONE, US, 1, 3, true, 64, 0);
    let a = feed(&mut n, t.plus(1000), &addba);
    let resp = transmits(&a)
        .into_iter()
        .find(|f| f.to == PHONE && f.bytes[24] == 3 && f.bytes[25] == 1)
        .expect("ADDBA Response sent");
    let resp_params = u16::from_le_bytes([resp.bytes[29], resp.bytes[30]]);
    assert_eq!(resp_params & 0x0003, 0x0003, "immediate BA + amsdu=1");
    assert_eq!(resp_params >> 6, 64);

    // Out-of-order: seq=1 is a 3-subframe x 1500B A-MSDU (~4.6 KiB),
    // seq=2 is a 5-subframe x 1500B A-MSDU (~7.7 KiB), then seq=0 arrives.
    let p0 = ipv6_tagged(PHONE, US, 10, 1500);
    let p1s: Vec<Ipv6Packet> = (11..=13).map(|tag| ipv6_tagged(PHONE, US, tag, 1500)).collect();
    let p2s: Vec<Ipv6Packet> = (14..=18).map(|tag| ipv6_tagged(PHONE, US, tag, 1500)).collect();
    let p1_refs: Vec<&[u8]> = p1s.iter().map(|p| p.data.as_slice()).collect();
    let p2_refs: Vec<&[u8]> = p2s.iter().map(|p| p.data.as_slice()).collect();

    let f0 = frame::qos_data_frame(PHONE, US, 0, 10, &p0.data);
    let f1 = frame::amsdu_frame(PHONE, US, 1, 11, &p1_refs);
    let f2 = frame::amsdu_frame(PHONE, US, 2, 14, &p2_refs);
    assert!(f1.len() > 4500);
    assert!(f2.len() > 7500 && f2.len() < 8192);

    assert_eq!(delivered_tags(&feed(&mut n, t.plus(2000), &f2)), vec![]);
    assert_eq!(delivered_tags(&feed(&mut n, t.plus(2100), &f1)), vec![]);
    let out = feed(&mut n, t.plus(2200), &f0);
    assert_eq!(
        delivered_tags(&out),
        vec![10, 11, 12, 13, 14, 15, 16, 17, 18]
    );
    // Verify every delivered packet kept its full 1500-byte payload.
    let lens: Vec<usize> = out
        .iter()
        .filter_map(|act| match act {
            Action::Deliver(p) if p.data[6] == 6 => Some(p.data.len()),
            _ => None,
        })
        .collect();
    assert_eq!(lens, vec![1500; 9]);

    // When cfg.rx_amsdu == false, ADDBA Response clears bit 0 even if peer asks for amsdu=1.
    cfg.rx_amsdu = false;
    let mut n_off = Node::new(cfg, START);
    let t2 = meet(&mut n_off, &seq(PHONE_SEQ));
    let a2 = feed(&mut n_off, t2.plus(1000), &addba);
    let resp2 = transmits(&a2)
        .into_iter()
        .find(|f| f.to == PHONE && f.bytes[24] == 3 && f.bytes[25] == 1)
        .expect("ADDBA Response sent");
    let resp2_params = u16::from_le_bytes([resp2.bytes[29], resp2.bytes[30]]);
    assert_eq!(resp2_params & 0x0003, 0x0002, "amsdu=0 when rx_amsdu=false");
}

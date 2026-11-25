//! 802.11 RX Block Ack reorder buffer (one session: one peer, one TID).
//!
//! When a peer transmits A-MPDUs under an accepted ADDBA session, MPDUs that
//! are retransmitted after a BlockAck hole arrive after higher-sequence MPDUs.
//! Delivering them in arrival order causes TCP out-of-order SACK stalls.
//!
//! This buffer holds up to [`BA_REORDER_SLOTS`] (64) out-of-order frames by
//! their 12-bit 802.11 sequence number and releases them strictly in sequence
//! order. Holes are skipped on a BlockAckReq (BAR), when the sequence window
//! advances past them, or after [`BA_REORDER_TIMEOUT_US`]. Duplicates and
//! frames behind the window are dropped.

use alloc::vec::Vec;

use crate::Time;

/// Maximum Block Ack reorder window size (802.11n/ac/ax 64-MPDU window).
pub const BA_REORDER_SLOTS: usize = 64;
/// Number of 802.11 QoS TIDs tracked per peer (`0..8`).
pub const BA_REORDER_TIDS: usize = 8;
/// Maximum time a buffered successor waits behind a missing sequence hole
/// before the hole is skipped (60 ms).
pub const BA_REORDER_TIMEOUT_US: u64 = 60_000;

const SEQ_MASK: u16 = 0x0fff;
const SEQ_HALF: u16 = 2048;

#[inline]
fn seq_diff(a: u16, b: u16) -> u16 {
    a.wrapping_sub(b) & SEQ_MASK
}

#[inline]
pub fn clamp_win_size(win_size: u16) -> usize {
    let w = win_size as usize;
    if w == 0 || w > BA_REORDER_SLOTS {
        BA_REORDER_SLOTS
    } else {
        w
    }
}

/// Diagnostic counters for one Block Ack reorder session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BaStats {
    pub in_order: u64,
    pub reordered: u64,
    pub duplicates: u64,
    pub holes_skipped: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Slot<T> {
    item: T,
    received_at: Time,
}

/// What the caller must deliver after feeding one received QoS Data MPDU into
/// [`BaReorder::rx`].
#[derive(Debug, PartialEq, Eq)]
pub enum RxOutcome<T> {
    /// Duplicate or behind the receive window: drop without delivering.
    Duplicate,
    /// In-order fast path: deliver `before` (if the window advanced first),
    /// then the current frame directly, then `after` (any buffered successors).
    DeliverNow { before: Vec<T>, after: Vec<T> },
    /// Current frame was buffered out-of-order; deliver `before` if advancing
    /// the window released older held frames.
    Buffered { before: Vec<T> },
}

/// 64-slot 802.11 RX Block Ack reorder buffer for one peer and one TID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaReorder<T> {
    head: u16,
    size: usize,
    stored: usize,
    token: u8,
    initial_ssn: u16,
    slots: Vec<Option<Slot<T>>>,
    stats: BaStats,
}

impl<T> BaReorder<T> {
    /// Starts a new reorder session at starting sequence number `ssn` with
    /// negotiated window size `win_size` (clamped to `1..=64`).
    pub fn new(ssn: u16, win_size: u16, token: u8) -> Self {
        let ssn = ssn & SEQ_MASK;
        let size = clamp_win_size(win_size);
        let mut slots = Vec::with_capacity(BA_REORDER_SLOTS);
        slots.resize_with(BA_REORDER_SLOTS, || None);
        Self {
            head: ssn,
            size,
            stored: 0,
            token,
            initial_ssn: ssn,
            slots,
            stats: BaStats::default(),
        }
    }

    pub fn head(&self) -> u16 {
        self.head
    }

    pub fn win_size(&self) -> usize {
        self.size
    }

    pub fn stored(&self) -> usize {
        self.stored
    }

    pub fn stats(&self) -> BaStats {
        self.stats
    }

    /// True if a retransmitted ADDBA Request matches this already-active
    /// session's parameters, so the buffer should not be reset.
    pub fn matches_session(&self, token: u8, ssn: u16, win_size: u16) -> bool {
        self.token == token
            && self.initial_ssn == (ssn & SEQ_MASK)
            && self.size == clamp_win_size(win_size)
    }

    /// Processes an incoming QoS Data frame with 12-bit sequence number `seq`.
    /// `make_held` is only invoked when the frame must be buffered out of
    /// order, keeping the in-order fast path allocation-free.
    pub fn rx(&mut self, seq: u16, now: Time, make_held: impl FnOnce() -> T) -> RxOutcome<T> {
        let seq = seq & SEQ_MASK;
        let d = seq_diff(seq, self.head);
        if d >= SEQ_HALF {
            self.stats.duplicates += 1;
            return RxOutcome::Duplicate;
        }
        let mut before = Vec::new();
        if d as usize >= self.size {
            let new_head = seq.wrapping_sub(self.size as u16).wrapping_add(1) & SEQ_MASK;
            self.advance_to(new_head, &mut before);
            self.release_ready(&mut before);
        }
        let idx = (seq as usize) % BA_REORDER_SLOTS;
        if seq == self.head && self.slots[idx].is_none() {
            self.stats.in_order += 1;
            self.head = (self.head + 1) & SEQ_MASK;
            let mut after = Vec::new();
            self.release_ready(&mut after);
            return RxOutcome::DeliverNow { before, after };
        }
        if self.slots[idx].is_some() {
            self.stats.duplicates += 1;
            return if before.is_empty() {
                RxOutcome::Duplicate
            } else {
                RxOutcome::Buffered { before }
            };
        }
        self.slots[idx] = Some(Slot {
            item: make_held(),
            received_at: now,
        });
        self.stored += 1;
        RxOutcome::Buffered { before }
    }

    /// Processes an 802.11 BlockAckReq (BAR): advances the window to `ssn`
    /// (unless `ssn` is behind `head`) and releases held frames in order.
    pub fn bar(&mut self, ssn: u16) -> Vec<T> {
        let mut out = Vec::new();
        let ssn = ssn & SEQ_MASK;
        if seq_diff(ssn, self.head) >= SEQ_HALF {
            return out;
        }
        self.advance_to(ssn, &mut out);
        self.release_ready(&mut out);
        out
    }

    /// Flushes stale holes whose buffered successor has waited at least
    /// [`BA_REORDER_TIMEOUT_US`].
    pub fn timeout(&mut self, now: Time) -> Vec<T> {
        let mut out = Vec::new();
        if self.stored == 0 {
            return out;
        }
        // Scan from the furthest slot down so a newly arrived earlier frame
        // cannot hide an older expired successor behind a hole.
        for k in (1..self.size).rev() {
            let seq = (self.head + k as u16) & SEQ_MASK;
            let idx = (seq as usize) % BA_REORDER_SLOTS;
            if let Some(slot) = &self.slots[idx]
                && now.since(slot.received_at) >= BA_REORDER_TIMEOUT_US
            {
                self.advance_to(seq, &mut out);
                self.release_ready(&mut out);
                return out;
            }
        }
        out
    }

    /// Earliest time at which a currently buffered frame will trigger a hole
    /// timeout, or `None` when no frames are held.
    pub fn next_timeout(&self) -> Option<Time> {
        if self.stored == 0 {
            return None;
        }
        let mut earliest: Option<Time> = None;
        for k in 1..self.size {
            let seq = (self.head + k as u16) & SEQ_MASK;
            let idx = (seq as usize) % BA_REORDER_SLOTS;
            if let Some(slot) = &self.slots[idx] {
                let exp = slot.received_at.plus(BA_REORDER_TIMEOUT_US);
                earliest = Some(match earliest {
                    Some(e) => e.min(exp),
                    None => exp,
                });
            }
        }
        earliest
    }

    /// Stops the session (e.g. on DELBA or session reset), flushing all held
    /// frames in sequence order.
    pub fn stop(&mut self) -> Vec<T> {
        let mut out = Vec::new();
        let mut remaining = self.size;
        while self.stored > 0 && remaining > 0 {
            let idx = (self.head as usize) % BA_REORDER_SLOTS;
            if let Some(slot) = self.slots[idx].take() {
                out.push(slot.item);
                self.stored -= 1;
                self.stats.reordered += 1;
            }
            self.head = (self.head + 1) & SEQ_MASK;
            remaining -= 1;
        }
        out
    }

    fn release_ready(&mut self, out: &mut Vec<T>) {
        while self.stored > 0 {
            let idx = (self.head as usize) % BA_REORDER_SLOTS;
            let Some(slot) = self.slots[idx].take() else {
                break;
            };
            out.push(slot.item);
            self.stored -= 1;
            self.stats.reordered += 1;
            self.head = (self.head + 1) & SEQ_MASK;
        }
    }

    fn advance_to(&mut self, new_head: u16, out: &mut Vec<T>) {
        let mut remaining = seq_diff(new_head, self.head);
        while remaining > 0 && self.stored > 0 {
            let idx = (self.head as usize) % BA_REORDER_SLOTS;
            if let Some(slot) = self.slots[idx].take() {
                out.push(slot.item);
                self.stored -= 1;
                self.stats.reordered += 1;
            } else {
                self.stats.holes_skipped += 1;
            }
            self.head = (self.head + 1) & SEQ_MASK;
            remaining -= 1;
        }
        if remaining > 0 {
            self.stats.holes_skipped += remaining as u64;
            self.head = new_head;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn deliver(r: &mut BaReorder<u16>, seq: u16, t: u64) -> Vec<u16> {
        match r.rx(seq, Time(t), || seq) {
            RxOutcome::Duplicate => Vec::new(),
            RxOutcome::DeliverNow { mut before, after } => {
                before.push(seq);
                before.extend(after);
                before
            }
            RxOutcome::Buffered { before } => before,
        }
    }

    #[test]
    fn in_order_fast_path_never_buffers() {
        let mut r = BaReorder::<u16>::new(10, 64, 1);
        let mut held_called = false;
        for s in 10..20 {
            let out = r.rx(s, Time(1000), || {
                held_called = true;
                s
            });
            assert_eq!(
                out,
                RxOutcome::DeliverNow {
                    before: vec![],
                    after: vec![]
                }
            );
        }
        assert!(!held_called);
        assert_eq!(r.head(), 20);
        assert_eq!(r.stored(), 0);
        assert_eq!(r.stats().in_order, 10);
        assert_eq!(r.next_timeout(), None);
    }

    #[test]
    fn out_of_order_releases_in_sequence_order() {
        let mut r = BaReorder::<u16>::new(0, 64, 1);
        assert_eq!(deliver(&mut r, 2, 100), vec![]);
        assert_eq!(deliver(&mut r, 1, 200), vec![]);
        assert_eq!(deliver(&mut r, 4, 300), vec![]);
        assert_eq!(r.stored(), 3);
        // Arriving seq 0 releases 0, 1, 2; seq 4 stays waiting for 3.
        assert_eq!(deliver(&mut r, 0, 400), vec![0, 1, 2]);
        assert_eq!(r.head(), 3);
        assert_eq!(r.stored(), 1);
        // Arriving seq 3 releases 3, 4.
        assert_eq!(deliver(&mut r, 3, 500), vec![3, 4]);
        assert_eq!(r.head(), 5);
        assert_eq!(r.stored(), 0);
        assert_eq!(r.stats().in_order, 2);
        assert_eq!(r.stats().reordered, 3);
    }

    #[test]
    fn duplicates_both_behind_and_inside_window_are_dropped() {
        let mut r = BaReorder::<u16>::new(5, 64, 1);
        assert_eq!(deliver(&mut r, 5, 100), vec![5]);
        // Behind head (already delivered)
        assert_eq!(deliver(&mut r, 5, 200), vec![]);
        assert_eq!(deliver(&mut r, 4, 200), vec![]);
        // Duplicate of a buffered frame inside window
        assert_eq!(deliver(&mut r, 7, 300), vec![]);
        assert_eq!(deliver(&mut r, 7, 400), vec![]);
        assert_eq!(r.stored(), 1);
        assert_eq!(r.stats().duplicates, 3);
        assert_eq!(deliver(&mut r, 6, 500), vec![6, 7]);
    }

    #[test]
    fn wrap_around_at_4095_to_0() {
        let mut r = BaReorder::<u16>::new(4094, 64, 1);
        // Out of order across 4095 -> 0 boundary
        assert_eq!(deliver(&mut r, 1, 100), vec![]);
        assert_eq!(deliver(&mut r, 0, 200), vec![]);
        assert_eq!(deliver(&mut r, 4095, 300), vec![]);
        assert_eq!(deliver(&mut r, 4094, 400), vec![4094, 4095, 0, 1]);
        assert_eq!(r.head(), 2);
        assert_eq!(r.stored(), 0);
        // Old seq 4095 is now behind head=2 and must be treated as duplicate.
        assert_eq!(deliver(&mut r, 4095, 500), vec![]);
        assert_eq!(r.stats().duplicates, 1);
    }

    #[test]
    fn window_advance_preserves_order_when_seq_lands_on_new_head() {
        let mut r = BaReorder::<u16>::new(0, 4, 1);
        // Hold 1, 2, 3 (hole at 0).
        assert_eq!(deliver(&mut r, 1, 100), vec![]);
        assert_eq!(deliver(&mut r, 2, 100), vec![]);
        assert_eq!(deliver(&mut r, 3, 100), vec![]);
        // Seq 4 is ahead of window [0, 4); must skip hole 0, deliver 1, 2, 3, then 4!
        assert_eq!(deliver(&mut r, 4, 200), vec![1, 2, 3, 4]);
        assert_eq!(r.head(), 5);
        assert_eq!(r.stored(), 0);
        assert_eq!(r.stats().holes_skipped, 1);
    }

    #[test]
    fn bar_advances_window_and_ignores_stale_bar() {
        let mut r = BaReorder::<u16>::new(100, 64, 1);
        assert_eq!(deliver(&mut r, 102, 100), vec![]);
        assert_eq!(deliver(&mut r, 103, 100), vec![]);
        assert_eq!(deliver(&mut r, 105, 100), vec![]);
        // Stale BAR behind head=100 is ignored.
        assert_eq!(r.bar(99), vec![]);
        assert_eq!(r.head(), 100);
        // BAR with SSN=102 skips holes 100, 101 and releases 102, 103.
        assert_eq!(r.bar(102), vec![102, 103]);
        assert_eq!(r.head(), 104);
        assert_eq!(r.stored(), 1);
        // BAR past 105 releases 105 and advances head to 108.
        assert_eq!(r.bar(108), vec![105]);
        assert_eq!(r.head(), 108);
        assert_eq!(r.stored(), 0);
    }

    #[test]
    fn hole_timeout_flushes_stale_frames_in_order() {
        let mut r = BaReorder::<u16>::new(0, 64, 1);
        assert_eq!(deliver(&mut r, 3, 10_000), vec![]);
        assert_eq!(deliver(&mut r, 1, 20_000), vec![]);
        assert_eq!(r.next_timeout(), Some(Time(10_000 + BA_REORDER_TIMEOUT_US)));
        // Before timeout: nothing flushed.
        assert_eq!(r.timeout(Time(10_000 + BA_REORDER_TIMEOUT_US - 1)), vec![]);
        assert_eq!(r.stored(), 2);
        // At timeout of seq 3 (oldest held): skips holes 0 & 2, releases 1 then 3 in order.
        assert_eq!(
            r.timeout(Time(10_000 + BA_REORDER_TIMEOUT_US)),
            vec![1, 3]
        );
        assert_eq!(r.head(), 4);
        assert_eq!(r.stored(), 0);
        assert_eq!(r.stats().holes_skipped, 2);
    }

    #[test]
    fn stop_flushes_all_held_frames_in_order() {
        let mut r = BaReorder::<u16>::new(4094, 64, 1);
        assert_eq!(deliver(&mut r, 1, 100), vec![]);
        assert_eq!(deliver(&mut r, 4095, 100), vec![]);
        assert_eq!(r.stop(), vec![4095, 1]);
        assert_eq!(r.stored(), 0);
    }
}

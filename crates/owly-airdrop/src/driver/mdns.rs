//! An mDNS responder and browser for `_airdrop._tcp` on one interface, for
//! hosts without a system responder (MDNS-1, MDNS-3, MDNS-6), announcing in
//! the bursts the radio asks for (MDNS-7).

use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::Instant;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::sleep;

use crate::proto::mdns::{
    self, Announcer, Browser, Burst, MDNS_GROUP, MDNS_PORT, Message, Service,
};

/// DNS-SD on the interface with this scope ID.
#[derive(Debug, Clone)]
pub struct Mdns {
    scope_id: u32,
    burst: Option<Burst>,
}

/// A registered service, withdrawn when dropped.
pub struct Registration {
    _stop: oneshot::Sender<()>,
}

/// A running browse, which stops when dropped.
pub struct Browse {
    pub events: mpsc::Receiver<mdns::BrowseEvent>,
    _stop: oneshot::Sender<()>,
}

impl Mdns {
    pub fn new(scope_id: u32) -> Self {
        Mdns {
            scope_id,
            burst: None,
        }
    }

    /// Repeats the announcement in bursts for as long as the service is
    /// registered, for a radio that doesn't carry the records itself
    /// (MDNS-7). The radio's link says which, if any.
    pub fn with_burst(mut self, burst: Option<Burst>) -> Self {
        self.burst = burst;
        self
    }

    /// Publishes a receiver's service until the registration is dropped
    /// (MDNS-1).
    pub async fn register(&self, service: Service) -> io::Result<Registration> {
        let socket = self.socket()?;
        let (stop, stopped) = oneshot::channel::<()>();
        let this = self.clone();
        tokio::spawn(async move { this.respond(socket, service, stopped).await });
        Ok(Registration { _stop: stop })
    }

    /// Browses `_airdrop._tcp` until the browse is dropped (MDNS-6).
    pub async fn browse(&self) -> io::Result<Browse> {
        let socket = self.socket()?;
        let (events, rx) = mpsc::channel(64);
        let (stop, stopped) = oneshot::channel::<()>();
        let this = self.clone();
        tokio::spawn(async move { this.browse_loop(socket, events, stopped).await });
        Ok(Browse {
            events: rx,
            _stop: stop,
        })
    }

    fn socket(&self) -> io::Result<UdpSocket> {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_only_v6(true)?;
        socket.set_reuse_address(true)?;
        #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
        socket.set_reuse_port(true)?;
        socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, MDNS_PORT)).into())?;
        socket.join_multicast_v6(&MDNS_GROUP, self.scope_id)?;
        socket.set_multicast_if_v6(self.scope_id)?;
        socket.set_multicast_hops_v6(255)?;
        socket.set_multicast_loop_v6(false)?;
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket.into())
    }

    fn group(&self) -> SocketAddrV6 {
        SocketAddrV6::new(MDNS_GROUP, MDNS_PORT, 0, self.scope_id)
    }

    /// Only link-local packets from this interface count; on Windows a socket
    /// bound to `[::]:5353` also receives LAN/VPN queries whose global/ULA
    /// source addresses have `scope_id == 0`, and answering those leaks
    /// `_airdrop._tcp.local` onto Ethernet/Wi-Fi LAN causing duplicate AirDrop
    /// icons on iOS.
    fn on_this_link(&self, from: SocketAddr) -> Option<SocketAddrV6> {
        match from {
            SocketAddr::V6(from)
                if self.scope_id != 0
                    && from.scope_id() == self.scope_id
                    && (from.ip().segments()[0] & 0xffc0 == 0xfe80) =>
            {
                Some(from)
            }
            _ => None,
        }
    }

    async fn respond(
        self,
        socket: UdpSocket,
        service: Service,
        mut stopped: oneshot::Receiver<()>,
    ) {
        let group = self.group();
        let announcement = service.announcement();
        let mut announcer = Announcer::new(self.burst, Instant::now());
        let mut buf = vec![0; mdns::MAX_MESSAGE];
        loop {
            let next = announcer.next_timer();
            let wait = next.map(|at| at.saturating_duration_since(Instant::now()));
            tokio::select! {
                _ = &mut stopped => break,
                () = sleep(wait.unwrap_or_default()), if wait.is_some() => {
                    if announcer.on_timer(Instant::now()) {
                        let _ = socket.send_to(&announcement, group).await;
                    }
                }
                received = socket.recv_from(&mut buf) => {
                    let Ok((n, from)) = received else { continue };
                    let Some(from) = self.on_this_link(from) else { continue };
                    let Ok(query) = Message::decode(&buf[..n]) else { continue };
                    let Some(reply) = service.answer(&query, from.port() != MDNS_PORT) else { continue };
                    let to = if reply.unicast { from } else { group };
                    // RFC 6762 §6: a short random delay for shared records
                    // isn't needed with one responder per link.
                    let _ = socket.send_to(&reply.message, to).await;
                }
            }
        }
        // Withdraw the records (RFC 6762 §10.1).
        let _ = socket.send_to(&service.goodbye(), group).await;
    }

    async fn browse_loop(
        self,
        socket: UdpSocket,
        events: mpsc::Sender<mdns::BrowseEvent>,
        mut stopped: oneshot::Receiver<()>,
    ) {
        let group = self.group();
        let mut browser = Browser::new(Instant::now());
        let mut buf = vec![0; mdns::MAX_MESSAGE];
        loop {
            let deadline = browser.next_timer();
            let wait = deadline.saturating_duration_since(Instant::now());
            tokio::select! {
                _ = &mut stopped => return,
                () = events.closed() => return,
                () = sleep(wait) => {
                    if let Some(query) = browser.on_timer(Instant::now()) {
                        let _ = socket.send_to(&query, group).await;
                    }
                }
                received = socket.recv_from(&mut buf) => {
                    let Ok((n, from)) = received else { continue };
                    if self.on_this_link(from).is_none() {
                        continue;
                    }
                    if let Ok(message) = Message::decode(&buf[..n]) {
                        browser.handle(&message, Instant::now());
                    }
                }
            }
            while let Some(event) = browser.poll_event() {
                if events.send(event).await.is_err() {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn on_this_link_accepts_only_link_local_on_bound_scope() {
        let mdns = Mdns::new(2);
        let awdl_peer = SocketAddr::V6(SocketAddrV6::new(
            "fe80::24:30ff:fe57:cacf".parse().unwrap(),
            5353,
            0,
            2,
        ));
        assert_eq!(mdns.on_this_link(awdl_peer).map(SocketAddr::V6), Some(awdl_peer));

        // Rejects another interface's link-local (e.g. Ethernet LAN ifIndex 5).
        let lan_ll = SocketAddr::V6(SocketAddrV6::new(
            "fe80::24:30ff:fe57:cacf".parse().unwrap(),
            5353,
            0,
            5,
        ));
        assert_eq!(mdns.on_this_link(lan_ll), None);

        // Rejects global/ULA IPv6 with scope_id == 0 (prevents LAN mDNS leak).
        let lan_global = SocketAddr::V6(SocketAddrV6::new(
            "2001:db8::1".parse().unwrap(),
            5353,
            0,
            0,
        ));
        assert_eq!(mdns.on_this_link(lan_global), None);

        // Rejects link-local with missing scope_id == 0.
        let ll_no_scope = SocketAddr::V6(SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            5353,
            0,
            0,
        ));
        assert_eq!(mdns.on_this_link(ll_no_scope), None);

        // Rejects IPv4.
        let v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5353));
        assert_eq!(mdns.on_this_link(v4), None);
    }
}

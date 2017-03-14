// Copyright 2017 Sopium

// This file is part of TiTun.

// TiTun is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// TiTun is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with TiTun.  If not, see <https://www.gnu.org/licenses/>.

extern crate tai64;
extern crate treebitmap;

use self::tai64::TAI64N;
use self::treebitmap::{IpLookupTable, IpLookupTableOps};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex, RwLock};
use std::sync::mpsc::{RecvTimeoutError, Sender, channel};
use std::thread::{Builder, JoinHandle, sleep};
use std::time::{Duration, Instant};
use tun::Tun;
use wireguard::*;

// Increase if your MTU is larger...
const BUFSIZE: usize = 1500;

type SharedPeerState = Arc<RwLock<PeerState>>;

pub struct WgState {
    info: RwLock<WgInfo>,

    pubkey_map: RwLock<HashMap<X25519Pubkey, SharedPeerState>>,
    // Care must be taken to keep this in sync with `SharedPeerState`s.
    id_map: RwLock<HashMap<Id, SharedPeerState>>,
    // Also should be keep in sync. But these should change less often.
    rt4: RwLock<IpLookupTable<Ipv4Addr, SharedPeerState>>,
    rt6: RwLock<IpLookupTable<Ipv6Addr, SharedPeerState>>,
}

struct PeerState {
    info: PeerInfo,
    last_handshake: Option<TAI64N>,
    cookie: Option<Cookie>,
    last_mac1: Option<[u8; 16]>,
    handshake: Option<Handshake>,
    primary_transport: Option<Transport>,
    secondary_transport: Option<Transport>,
}

struct Handshake {
    self_id: Id,
    sender: Mutex<Sender<(SocketAddr, Vec<u8>)>>,
}

fn udp_get_handshake_init(wg: &WgState, sock: &UdpSocket, p: Vec<u8>, addr: SocketAddr) {
    if p.len() != 148 {
        return;
    }

    let mut p = p;
    p.truncate(132);

    let info = wg.info.read().unwrap();

    if let Ok(mut r) = process_initiation(info.deref(), &p) {
        let r_pubkey = r.handshake_state.get_rs().unwrap();
        if let Some(peer) = wg.pubkey_map
            .read()
            .unwrap()
            .get(&r_pubkey) {
            let peer_clone = peer.clone();
            let mut peer = peer.write().unwrap();

            // Compare timestamp.
            if Some(r.timestamp) > peer.last_handshake {
                peer.last_handshake = Some(r.timestamp);
            } else {
                debug!("Handshake timestamp smaller.");
                return;
            }

            let self_id = Id::gen();
            let mut response = responde(info.deref(), &mut r, self_id);
            cookie_sign(&mut response, peer.cookie.as_ref());
            sock.send_to(&response, addr).unwrap();

            let t = Transport::new_from_hs(self_id, r.peer_id, r.handshake_state);
            wg.id_map
                .write()
                .unwrap()
                .insert(self_id, peer_clone);
            peer.info.endpoint = Some(addr);
            peer.rotate_transport(t,
                                  wg.id_map
                                      .write()
                                      .unwrap()
                                      .deref_mut());
            info!("Handshake successful as responder.");
        } else {
            debug!("Get handshake init, but can't find peer by pubkey.");
        }
    } else {
        debug!("Get handshake init, but authentication/decryption failed.");
    }
}

fn udp_get_handshake_resp(wg: &WgState, p: Vec<u8>, addr: SocketAddr) {
    let self_id = Id::from_slice(&p[8..12]);

    if let Some(peer) = wg.id_map
        .read()
        .unwrap()
        .get(&self_id) {
        let peer = peer.read().unwrap();
        let handshake = peer.handshake.as_ref().unwrap();
        if handshake.self_id != self_id {
            return;
        }
        handshake.sender
            .lock()
            .unwrap()
            .send((addr, p))
            .unwrap();
    } else {
        debug!("Get handshake response message, but don't know id.");
    }
}

fn udp_get_cookie_reply(wg: &WgState, p: Vec<u8>) {
    let self_id = Id::from_slice(&p[4..8]);

    if let Some(peer) = wg.id_map
        .read()
        .unwrap()
        .get(&self_id) {
        let mut peer = peer.write().unwrap();
        if let Some(mac1) = peer.last_mac1 {
            let info = wg.info.read().unwrap();
            if let Ok(cookie) = process_cookie_reply(info.psk.as_ref(),
                                                     &peer.info.peer_pubkey,
                                                     &mac1,
                                                     &p) {
                peer.cookie = Some(cookie);
            } else {
                debug!("Get cookie reply message, but auth/decryption failed.");
            }
        }
    } else {
        debug!("Get cookie reply message, but don't know id.");
    }
}

fn udp_get_transport(wg: &WgState, tun: &Tun, p: Vec<u8>, addr: SocketAddr) {
    let self_id = Id::from_slice(&p[4..8]);

    if let Some(peer0) = wg.id_map
        .read()
        .unwrap()
        .get(&self_id) {
        let should_set_endpoint = {
            let peer = peer0.read().unwrap();
            if let Some(t) = peer.find_transport_by_id(self_id) {
                if let Ok(mut pkt) = t.decrypt(&p) {
                    if let Ok((len, src, _)) = parse_ip_packet(&pkt) {
                        // Reverse path filtering.
                        let peer1 = match src {
                            IpAddr::V4(a4) => {
                                wg.rt4
                                    .read()
                                    .unwrap()
                                    .longest_match(a4)
                                    .map(|x| x.2.clone())
                            }
                            IpAddr::V6(a6) => {
                                wg.rt6
                                    .read()
                                    .unwrap()
                                    .longest_match(a6)
                                    .map(|x| x.2.clone())
                            }
                        };
                        if peer1.is_none() || !Arc::ptr_eq(peer0, &peer1.unwrap()) {
                            debug!("Get transport message: allowed IPs check failed.");
                        } else {
                            pkt.truncate(len as usize);
                            tun.write(&pkt).unwrap();
                        }
                    }
                    peer.info.endpoint != Some(addr)
                } else {
                    debug!("Get transport message, decryption failed.");
                    false
                }
            } else {
                false
            }
        };
        if should_set_endpoint {
            peer0.write()
                .unwrap()
                .info
                .endpoint = Some(addr);
        }
    } else {
        debug!("Get transport message, but don't know id.");
    }
}

/// Start a new thread to recv and process UDP packets.
///
/// This thread runs forever. XXX: how to monitor that?
pub fn start_udp_recv(wg: Arc<WgState>, sock: Arc<UdpSocket>, tun: Arc<Tun>) -> JoinHandle<()> {
    Builder::new().name("UDP".to_string()).spawn(move || loop {
        let mut p = vec![0u8; BUFSIZE];
        let (len, addr) = sock.recv_from(&mut p).unwrap();

        if len < 12 {
            continue;
        }
        p.truncate(len);

        match p[0] {
            1 => udp_get_handshake_init(wg.as_ref(), &sock, p, addr),
            2 => udp_get_handshake_resp(wg.as_ref(), p, addr),
            3 => udp_get_cookie_reply(wg.as_ref(), p),
            4 => udp_get_transport(wg.as_ref(), &tun, p, addr),
            _ => (),
        }
    }).unwrap()
}

/// Start a new thread to read and process packets from TUN device.
///
/// This thread runs forever.
pub fn start_packet_read(wg: Arc<WgState>, sock: Arc<UdpSocket>, tun: Arc<Tun>) -> JoinHandle<()> {
    Builder::new().name("TUN".to_string()).spawn(move || {
        loop {
            let mut pkt = vec![0u8; BUFSIZE];
            let len = tun.read(&mut pkt).unwrap();
            pkt.truncate(len);

            if let Ok((_, _, dst)) = parse_ip_packet(&pkt) {
                let peer = {
                    match dst {
                        IpAddr::V4(a4) => {
                            wg.rt4
                                .read()
                                .unwrap()
                                .longest_match(a4)
                                .map(|a| a.2.clone())
                        }
                        IpAddr::V6(a6) => {
                            wg.rt6
                                .read()
                                .unwrap()
                                .longest_match(a6)
                                .map(|a| a.2.clone())
                        }
                    }
                };
                if peer.is_none() {
                    debug!("Get packet but don't know which peer to send to.");
                    continue;
                }
                let peer0 = peer.unwrap();
                let peer = peer0.read().unwrap();
                if peer.info.endpoint.is_none() {
                    // Don't know peer endpoint address.
                    continue;
                }
                if let Some(ref t) = peer.primary_transport {
                    let a = peer.info.endpoint.unwrap();
                    let encrypted = t.encrypt(&pkt);
                    if encrypted.is_err() {
                        continue;
                    }
                    sock.send_to(&encrypted.unwrap(), a).unwrap();
                } else if peer.handshake.is_none() {
                    start_handshake(wg.clone(), peer0.clone(), sock.clone());
                }
            } else {
                error!("Get packet from TUN device, but failed to parse it.");
            }
        }
    }).unwrap()
}

/// Start a new thread to do handshake.
///
/// Peer endpoint MUST be known.
///
/// The thread will terminate :
///  1. when the `Sender` is dropped.
///  2. after `REKEY_ATTEMPT_TIME`, i.e., 90 seconds.
///
/// When the thread terminates but handshake is not successful,
/// it is removed from `id_map` automatically.
fn start_handshake(wg: Arc<WgState>,
                   peer: SharedPeerState,
                   sock: Arc<UdpSocket>)
                   -> JoinHandle<()> {
    Builder::new().name("handshake".to_string()).spawn(move || loop {
        let (tx, rx) = channel::<(SocketAddr, Vec<u8>)>();
        let id = Id::gen();
        debug!("start handshake {:?}", id);
        peer.write().unwrap().handshake = Some(Handshake {
            self_id: id,
            sender: Mutex::new(tx),
        });
        wg.id_map
            .write()
            .unwrap()
            .insert(id, peer.clone());

        let rekey_timeout = Duration::from_secs(REKEY_TIMEOUT);
        let attemp_deadline = Instant::now() + Duration::from_secs(REKEY_ATTEMPT_TIME);
        loop {
            let ts = Instant::now();

            if ts >= attemp_deadline {
                wg.id_map
                    .write()
                    .unwrap()
                    .remove(&id);
                peer.write().unwrap().handshake = None;
                return;
            }

            let hs = {
                let mut peer = peer.write().unwrap();
                let (mut i, hs) = initiate(wg.info
                                               .read()
                                               .unwrap()
                                               .deref(),
                                           &peer.info,
                                           id);

                // Extract and save mac1.
                let mut mac1 = [0u8; 16];
                mac1.copy_from_slice(&i[116..132]);
                peer.last_mac1 = Some(mac1);

                cookie_sign(&mut i, peer.cookie.as_ref());
                let addr = *peer.info
                    .endpoint
                    .as_ref()
                    .unwrap();
                sock.send_to(&i, addr).unwrap();
                hs
            };

            loop {
                let elapsed = ts.elapsed();
                if elapsed >= rekey_timeout {
                    break;
                }
                let remaining = rekey_timeout - elapsed;
                match rx.recv_timeout(remaining) {
                    Ok((a, mut r)) => {
                        let mut hs = hs.clone();
                        r.truncate(76);
                        if let Ok(peer_id) = process_response(wg.info
                                                                  .read()
                                                                  .unwrap()
                                                                  .deref(),
                                                              &mut hs,
                                                              &r) {
                            let mut peer = peer.write().unwrap();

                            let t = Transport::new_from_hs(id, peer_id, hs);

                            peer.info.endpoint = Some(a);
                            peer.rotate_transport(t,
                                                  wg.id_map
                                                      .write()
                                                      .unwrap()
                                                      .deref_mut());
                            peer.handshake = None;

                            // Handshake completed, return.
                            // The `id_map` entry don't need to change.
                            info!("Handshake successful as initiator.");
                            return;
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => break,
                    Err(RecvTimeoutError::Disconnected) => {
                        wg.id_map
                            .write()
                            .unwrap()
                            .remove(&id);
                        return;
                    }
                }
            }
        }
    }).unwrap()
}

/// Start a new thread to do passive keep-alive, and drop expired transport sessions, etc.
///
/// This thread runs forever.
pub fn start_maintaining_thread(wg: Arc<WgState>, sock: Arc<UdpSocket>) -> JoinHandle<()> {
    Builder::new().name("maintaining".to_string()).spawn(move || loop {
        sleep(Duration::from_secs(1));

        // Detect id map leaks.
        let mut to_remove = Vec::new();
        for (i, p) in wg.id_map
            .read()
            .unwrap()
            .deref() {
            if !p.read().unwrap().has_id(*i) {
                error!("Id map leak detected!");
                to_remove.push(*i);
            }
        }
        for i in to_remove {
            wg.id_map
                .write()
                .unwrap()
                .remove(&i);
        }

        for peer0 in wg.pubkey_map
            .read()
            .unwrap()
            .values() {
            let (p, s) = {
                // Only acquire read lock if there is no need to modify peer,
                // which should be the common case.
                let peer = peer0.read().unwrap();

                let delete_id_p = if let Some(t) = peer.primary_transport.as_ref() {
                    if t.should_delete() {
                        let id = t.get_self_id();
                        wg.id_map
                            .write()
                            .unwrap()
                            .remove(&id);
                        Some(id)
                    } else {
                        if t.should_keepalive() {
                            if let Ok(p) = t.encrypt(&[]) {
                                sock.send_to(&p, peer.info.endpoint.unwrap()).unwrap();
                            }
                        }
                        if t.should_rekey() && peer.handshake.is_none() {
                            start_handshake(wg.clone(), peer0.clone(), sock.clone());
                        }
                        None
                    }
                } else {
                    None
                };

                let delete_id_s = if let Some(t) = peer.secondary_transport.as_ref() {
                    if t.should_delete() {
                        let id = t.get_self_id();
                        wg.id_map
                            .write()
                            .unwrap()
                            .remove(&id);
                        Some(id)
                    } else {
                        if t.should_keepalive() {
                            if let Ok(p) = t.encrypt(&[]) {
                                sock.send_to(&p, peer.info.endpoint.unwrap()).unwrap();
                            }
                        }
                        // Shouldn't re-key because of previous session, shall we?
                        None
                    }
                } else {
                    None
                };
                (delete_id_p, delete_id_s)
            };
            if p.is_some() || s.is_some() {
                let mut peer = peer0.write().unwrap();

                p.map(|id| peer.remove_peer_by_id(id));
                s.map(|id| peer.remove_peer_by_id(id));
            }
        }
    }).unwrap()
}

impl WgState {
    pub fn new(info: WgInfo, peers: &[PeerInfo]) -> Arc<WgState> {
        let mut pubkey_map = HashMap::new();

        let mut rt4 = IpLookupTable::new();
        let mut rt6 = IpLookupTable::new();

        for p in peers {
            let ps = PeerState {
                info: p.clone(),
                last_handshake: None,
                last_mac1: None,
                cookie: None,
                handshake: None,
                primary_transport: None,
                secondary_transport: None,
            };
            let ps = Arc::new(RwLock::new(ps));
            for &(a, prefix) in &p.allowed_ips {
                match a {
                    IpAddr::V4(a4) => rt4.insert(a4, prefix, ps.clone()),
                    IpAddr::V6(a6) => rt6.insert(a6, prefix, ps.clone()),
                };
            }
            pubkey_map.insert(p.peer_pubkey, ps);
        }

        Arc::new(WgState {
            info: RwLock::new(info),
            pubkey_map: RwLock::new(pubkey_map),
            id_map: RwLock::new(HashMap::new()),
            rt4: RwLock::new(rt4),
            rt6: RwLock::new(rt6),
        })
    }
}

impl PeerState {
    pub fn rotate_transport(&mut self, t: Transport, id_map: &mut HashMap<Id, SharedPeerState>) {
        if self.secondary_transport.is_some() {
            id_map.remove(&self.secondary_transport
                .take()
                .unwrap()
                .get_self_id());
        }
        self.secondary_transport = self.primary_transport.take();
        self.primary_transport = Some(t);
    }

    pub fn remove_peer_by_id(&mut self, id: Id) {
        if self.primary_transport.as_ref().map_or(false, |t| t.get_self_id() == id) {
            self.primary_transport = None;
        }
        if self.secondary_transport.as_ref().map_or(false, |t| t.get_self_id() == id) {
            self.secondary_transport = None;
        }
    }

    pub fn find_transport_by_id(&self, id: Id) -> Option<&Transport> {
        if let Some(t) = self.primary_transport.as_ref() {
            if t.get_self_id() == id {
                return Some(t);
            }
        }
        if let Some(t) = self.secondary_transport.as_ref() {
            if t.get_self_id() == id {
                return Some(t);
            }
        }
        None
    }

    pub fn has_id(&self, id: Id) -> bool {
        if let Some(ref h) = self.handshake {
            if h.self_id == id {
                return true;
            }
        }
        if let Some(ref t) = self.primary_transport {
            if t.get_self_id() == id {
                return true;
            }
        }
        if let Some(ref t) = self.secondary_transport {
            if t.get_self_id() == id {
                return true;
            }
        }
        false
    }
}

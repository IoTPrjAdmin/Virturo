// ----------------------------------------------------------------------------
// Copyright (c) 2025 LeoxTec https://leoxtec.com.
// Licensed under the MIT License.
// ----------------------------------------------------------------------------

//!
//! Infrastructure for packet routing
//!
//! Each forward rule defines original and forward interfaces.
//! Separate Routing object is bound to each of the interfaces with
//! their respective interface, endpoint data and forward interface and endpoint.
//!
//! There are 2 types of routing objects, one that bound to original interface and
//! a second bound to forward interface.
//!
//! Routing object bound to original interface contains patterns with respective
//! ports to forward.
//!
//! Packet routing entries, from origin to destination and from origin to forward
//! are hosted in a list (Hashmap) and are shared with different keys, such that
//! both forward and reverse routing will be possible.
//!
//!
//!
//!
//!
//!
//!
use anyhow::anyhow;
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

pub use crate::app_config::*;
// pub use crate::app_utils::*;
pub use crate::packet_handler::*;
pub use crate::pattern_handler::*;

// Allow PacketRoutingEntry reference to be shared
pub type PacketRoutingEntryShared = Arc<RwLock<PacketRoutingEntry>>;
pub type PacketForwardDataShared = Arc<RwLock<PacketForwardData>>;
pub type PacketEntriesList = RwLock<HashMap<String, PacketRoutingEntryShared>>;

pub type PacketSenderChannel = std::sync::mpsc::Sender<PacketHolder>;
pub type PacketRecvChannel = std::sync::mpsc::Receiver<PacketHolder>;

// Routing direction for routing logic
#[derive(Copy, Clone, Debug)]
pub enum RoutingDirection {
    OriginToForward,
    ForwardToOrigin,
}

// Forward rules list, keep destination point
#[derive(Clone, Debug)]
pub struct PacketForwardRule {
    // Pattern to data for routing, can be empty
    pub fwd_dst_ep: IpEndPoint,
}

// Meta data of forwarded packets, to connect packet origin with forwarded
#[derive(Copy, Clone, Debug)]
pub struct PacketRoutingEntry {
    pub origin_src_ep: Option<IpEndPoint>,
    pub origin_dst_ep: Option<IpEndPoint>,

    // planned to be used
    // pub origin_src_mac: Option<MacAddr>,
    // pub origin_dst_mac: Option<MacAddr>,
    pub fwd_src_ep: Option<IpEndPoint>,
    // planned to be used
    pub _fwd_dst_ep: Option<IpEndPoint>,

    // Time stamp of entry last update
    pub ttl: SystemTime,
}

#[derive(Debug)]
// Holds pack destination routing and pattern
pub struct PacketForwardData {
    // TODO the following data should be set dynamically according and stored in list
    // Source end point to forward packet from (port should be assigned according to packet type)
    pub fwd_src_ep: IpEndPoint,
    // Destination IP address to forward packet to
    pub _fwd_dst_ep: IpEndPoint,

    // TODO add fwd source net interface

    // List of forwarded entries
    pub entries: PacketEntriesList,
}

// Required data for detecting and routing packets
#[derive(Clone, Debug)]
pub struct RoutingData {
    pub packet_tx_channel: PacketSenderChannel,

    pub route_dir: RoutingDirection,

    // inbound original interface
    pub net_intf_ip: IpAddr,
    pub net_intf_mac: MacAddr,

    // Inject configuration for routing, maybe to move to a separate struct
    pub print_all_packets: bool,

    // origin port to capture packet on
    pub org_port: u16,

    // Holds forward rules list for relevant to current routing object
    // key is forward port which is used for reverse lookup for packet
    // from forward to origin
    forward_rules: HashMap<u16, PacketForwardRule>,

    // Hold patterns in an optimized way to search for (sorted)
    patterns: PatternsHolder,
}

impl PacketForwardRule {
    pub fn new_empty() -> Self {
        Self {
            fwd_dst_ep: IpEndPoint::new_empty_ipv4(),
        }
    }
}

impl RoutingData {
    pub fn new(
        ch: PacketSenderChannel,
        route_dir: RoutingDirection,
        net_intf_ip: IpAddr,
        net_intf_mac: MacAddr,
        org_port: u16,
        print_all_packets: bool,
    ) -> Self {
        Self {
            packet_tx_channel: ch,
            route_dir,
            net_intf_ip,
            net_intf_mac,
            org_port,
            print_all_packets,
            forward_rules: HashMap::new(),
            patterns: PatternsHolder::new(),
        }
    }

    pub fn build_forward_rules(
        &mut self,
        cnf_fwd_rules: &CnfForwardPatternsList,
    ) -> anyhow::Result<()> {
        self.forward_rules.clear();
        // iterate over pattern detection rules from configuration file to build list of rules
        for cnf_rule in cnf_fwd_rules {
            let pattern_vec = match hexstr_to_vec(&cnf_rule.pattern_hex) {
                Ok(v) => v,
                Err(err) => {
                    return Err(anyhow!(
                        "Error converting {} to bytes: {}",
                        cnf_rule.pattern_hex,
                        err
                    ));
                }
            };

            let ip_addr = match IpAddr::from_str(&cnf_rule.fwd_dst_ip) {
                Ok(v) => v,
                Err(err) => {
                    return Err(anyhow!(
                        "Error converting {} to bytes: {}",
                        cnf_rule.fwd_dst_ip,
                        err
                    ));
                }
            };

            let fwd_ep = IpEndPoint::new(ip_addr, cnf_rule.fwd_dst_port);

            // create forward packet containing endpoint only
            let pkt_fwd_rule: PacketForwardRule = PacketForwardRule {
                fwd_dst_ep: fwd_ep,
            };
            self.forward_rules
                .insert(cnf_rule.fwd_dst_port, pkt_fwd_rule);

            self.patterns
                .add(cnf_rule.fwd_dst_port as u64, pattern_vec.as_slice());
        }
        self.patterns.sort_by_len_desc();
        Ok(())
    }

    pub fn build_forward_ports(
        &mut self,
        cnf_fwd_rules: &CnfForwardPatternsList,
    ) -> anyhow::Result<()> {
        // iterate over pattern detection rules from configuration file to build list of rules
        for cnf_rule in cnf_fwd_rules {
            self.forward_rules
                .insert(cnf_rule.fwd_dst_port, PacketForwardRule::new_empty());
        }
        Ok(())
    }

    // find pattern for given data and return pointer to forward rule
    pub fn find_forward_pattern(&self, data: &[u8]) -> Option<&PacketForwardRule> {
        match self.patterns.match_pattern_starts_with(data) {
            Some(id) => {
                // Get Packet forward rule by id
                return self.forward_rules.get(&(id as u16));
            }
            None => {}
        }
        None
    }

    // Match forward rule for original interface
    pub fn match_org_forward_rule(&self, port: u16, data: &[u8]) -> Option<&PacketForwardRule> {
        if self.org_port == port {
            return self.find_forward_pattern(data);
        }
        None
    }

    pub fn find_dst_forward_port(&self, port: u16) -> bool {
        self.forward_rules.contains_key(&port)
    }
}

impl PacketRoutingEntry {
    pub fn new_with_ep_all(
        origin_src_ep: IpEndPoint,
        origin_dst_ep: IpEndPoint,
        fwd_src_ep: IpEndPoint,
        fwd_dst_ep: IpEndPoint,
    ) -> Self {
        Self {
            origin_src_ep: Some(origin_src_ep),
            origin_dst_ep: Some(origin_dst_ep),
            // origin_src_mac: None,
            // origin_dst_mac: None,
            fwd_src_ep: Some(fwd_src_ep),
            _fwd_dst_ep: Some(fwd_dst_ep),
            ttl: SystemTime::now(),
        }
    }

    pub fn set_ttl(&mut self) {
        self.ttl = SystemTime::now();
    }

    pub fn get_ttl_diff_as_sec(&self) -> u64 {
        SystemTime::now()
            .duration_since(self.ttl)
            .unwrap()
            .as_secs()
    }
}

impl PacketForwardData {
    pub fn new(fwd_dst_ip: IpAddr, fwd_dst_port: u16, fwd_src_ip: IpAddr) -> Self {
        Self {
            fwd_src_ep: IpEndPoint {
                ip: fwd_src_ip,
                port: 0,
            },
            _fwd_dst_ep: IpEndPoint {
                ip: fwd_dst_ip,
                port: fwd_dst_port,
            },
            entries: RwLock::new(HashMap::new()),
        }
    }

    fn create_key_entry(&self, ip: IpAddr, port: u16) -> String {
        String::from(format!("{}_{}", ip, port))
    }

    // create new entry or update existing if found,
    // Entry is shared with 2 keys, origin and forward
    pub fn new_entry_pair(
        &self,
        origin_src_ep: IpEndPoint,
        origin_dst_ep: IpEndPoint,
        fwd_src_ep: IpEndPoint,
        fwd_dst_ep: IpEndPoint,
    ) {
        let mut entries_wr = self.entries.write().unwrap();
        // Format key as source address and source port
        let fwd_key = self.create_key_entry(fwd_src_ep.ip, fwd_src_ep.port);
        // origin source ip address with source port
        let origin_key = self.create_key_entry(origin_src_ep.ip, origin_src_ep.port);
        // println!("key pair origin: {origin_key} fwd: {fwd_key} \n");
        match entries_wr.get_mut(&origin_key) {
            Some(entry) => {
                let mut entry_data = entry.write().unwrap();
                entry_data.set_ttl()
            }
            None => {
                let entry = Arc::new(RwLock::new(PacketRoutingEntry::new_with_ep_all(
                    origin_src_ep,
                    origin_dst_ep,
                    fwd_src_ep,
                    fwd_dst_ep,
                )));
                let org_entry_ptr = Arc::clone(&entry);
                let fwd_entry_ptr = Arc::clone(&entry);
                entries_wr.insert(fwd_key, org_entry_ptr);
                entries_wr.insert(origin_key, fwd_entry_ptr);
            }
        }
    }

    // Return entry (copy), according to port as part of the key,
    // if not found, return None
    pub fn find_entry(&self, ip: IpAddr, port: u16) -> Option<PacketRoutingEntry> {
        let key = self.create_key_entry(ip, port);
        let entries_rd = self.entries.read().unwrap();
        // println!("{}", key);
        let value = &entries_rd.get(&key);
        return match value {
            Some(v) => Some(v.read().unwrap().clone()),
            None => None,
        };
    }

    pub fn find_old_entries(&self, timeout: u32) -> Vec<String> {
        let entries_rd = self.entries.read().unwrap();
        // Collect entries to remove
        let list_to_remove: Vec<String> = entries_rd
            .iter()
            .filter_map(|(key, value)| {
                let val = value.read().unwrap();
                let diff = val.get_ttl_diff_as_sec();
                if diff > timeout as u64 {
                    // println!("{diff}");
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect();
        list_to_remove
    }

    pub fn remove_entries_by_list(&self, lst: &Vec<String>) -> usize {
        let mut cnt: usize = 0;
        if lst.len() > 0 {
            let mut entries_wr = self.entries.write().unwrap();
            for key in lst.iter() {
                if let Some(_) = entries_wr.remove(key) {
                    // TODO : remove for production
                    println!("{}: Removed entry {}", get_time_fmt(TIME_FMT), key);
                    cnt += 1;
                }
            }
        }
        cnt
    }

    #[allow(dead_code)]
    pub fn print_entries(&self) {
        let entries_rd = self.entries.read().unwrap();
        println!("Entries {:?}", entries_rd);
    }
}

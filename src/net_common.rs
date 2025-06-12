// ----------------------------------------------------------------------------
// Copyright (c) 2025 LeoxTec https://leoxtec.com.
// Licensed under the MIT License.
// ----------------------------------------------------------------------------

//!
//! Holds network common objects
//! 
//! 
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
//use pnet::packet::ip;
use rand;
use pnet::datalink::{self};
use pnet::util::MacAddr;


// const IPV4_LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
pub const IPV4_EMPTY: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));

// Defines end point for IP address (IPv4)
#[derive(Copy, Clone, Debug)]
pub struct IpEndPoint {
    pub ip: IpAddr,
    pub port: u16,
}

// Holds network interface with extracted fields
#[derive(Clone, Debug)]
pub struct NetInterfaceWrapper {
    pub net_name: String,
    pub phy_intf: datalink::NetworkInterface,
    pub net_intf_ip: IpAddr,
    pub net_intf_mac: MacAddr,
}


impl IpEndPoint {
    pub fn new_empty_ipv4 () -> Self {
        Self {
            ip : IPV4_EMPTY,
            port : 0
        }
    }

    pub fn new(ip : IpAddr, port: u16) -> Self {
        Self {
            ip,
            port,
        }
    }

    pub fn generate_udp_port(min: u16, max: u16) -> u16 {
        rand::random_range(min..=max)
    }

    // TODO : change to result without panic, move as method of IPEndPoint
    pub fn ip_as_ipv4(ip: &IpAddr) -> Ipv4Addr {
        match ip {
            IpAddr::V4(ip) => *ip,
            IpAddr::V6(_) => {
                panic!("Not supported IP address type ")
            }
        }
    }
}

impl fmt::Display for IpEndPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)?;
        Ok(())
    }
}

pub fn net_interface_find(interface_name: &str) -> Option<datalink::NetworkInterface> {
    // Get all network interfaces
    let interfaces = datalink::interfaces();
    let filter = |iface: &datalink::NetworkInterface| iface.name == interface_name;
    interfaces.into_iter().filter(filter).next()
}


pub fn net_interface_get(interface_name: &str) -> Option<NetInterfaceWrapper> {
    match net_interface_find(interface_name) {
        Some(net_intf) => {
            let net_intf_ptr = net_intf.clone();
            let net_ip_v4 = match net_intf.ips.iter().find(|&x| x.is_ipv4()) {
                Some(v) => v,
                None => {
                    return None;
                }
            };

            let net_mac_addr = match net_intf.mac {
                Some(v) => v,
                None => {
                    return None;
                }
            };

            let net_intf_wrapper = NetInterfaceWrapper {
                net_name: String::from(net_intf.name),
                phy_intf: net_intf_ptr,
                net_intf_ip: net_ip_v4.ip(),
                net_intf_mac: net_mac_addr,
            };
            return Some(net_intf_wrapper);
        }
        None => {}
    };
    None
}


pub fn list_net_interfaces() {
    let interfaces = datalink::interfaces();
    for interface in interfaces {
        println!("{:#?}", interface);
    }
}
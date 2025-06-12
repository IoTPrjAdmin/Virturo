// ----------------------------------------------------------------------------
// Copyright (c) 2025 LeoxTec https://leoxtec.com.
// Licensed under the MIT License.
// ----------------------------------------------------------------------------

//!
//! Stores network captured packets
//! 

//use std::collections::HashMap;
// use std::fmt;
use std::net::{IpAddr};
// use std::time::{Duration, SystemTime};
use std::vec;
use anyhow::{anyhow, Result};
// use pnet::datalink::{self};
use pnet::packet::ethernet::*;
// use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::udp::{ipv4_checksum, MutableUdpPacket, UdpPacket};
// use pnet::transport::{transport_channel, TransportChannelType, TransportSender};
use pnet::util::MacAddr;

// pub use crate::app_utils::*;
pub use crate::net_common::*;


pub const IPV4_HEADER_LEN: usize = 20;
//const IP_HEADER_LEN: usize = 5;
pub const UDP_HEADER_LEN: usize = 8;

pub const MAX_ETH_PACKET: usize = 1600;
pub const LOOPBACK_PACKET_MAX: usize = MAX_ETH_PACKET - IPV4_HEADER_LEN - UDP_HEADER_LEN;
pub const TRANSPORT_UDP_PACKET_MAX: usize = 4096;

pub const PEERPORT_PORT_MIN: u16 = 49152;
pub const PEERPORT_PORT_MAX: u16 = 65534;

#[derive(Clone, Debug)]
// Holds packet extracted data across several layers
pub struct PacketHolder {
    // define packet direction
    pub packet_dir: PacketRoutingDirection,
    // Planned to be used
    pub _packet_type: EtherType,

    // Network interface on which packet has been received or sent from
    pub net_intf_name: String,
    // Planned to be used
    pub _net_intf_mac: MacAddr,
    pub net_intf_ip: IpAddr,

    // MAC addresses of packet origin
    pub mac_src: MacAddr,
    pub mac_dst: MacAddr,

    // Holds origin source and destination IP end points
    // these are used for both incoming and outgoing packets
    pub org_src_ep: Option<IpEndPoint>,
    pub org_dst_ep: Option<IpEndPoint>,

    // Forward packet destination
    // pub fwd_mac : Option<MacAddr>,
    pub fwd_dst_ep: Option<IpEndPoint>,
    // IP address of source interface from where packet is forwarded from
    pub fwd_src_ep: Option<IpEndPoint>,

    // length of entire packet
    pub packet_len: usize,
    pub payload_len: usize,
    // Payload offset in packet buffer
    pub payload_offset : usize,
    // Holds entire packet data, including headers and payload
    pub packet_buff: Vec<u8>,
}

// Define packet routing directions, from origin or return to origin
#[derive(Clone, Debug)]
pub enum PacketRoutingDirection {
    // Packet received, but not yet processed
    Ipv4NotDetermined,
    // Packet received from origin (application), to be routed to forward destinations
    Ipv4UdpOrgToFwd,
    // Packet received from relayed side, to be sent to origin
    Ipv4UdpFwdToOrg,
    // Special packet type to indicate termination of listening thread on channel.
    // TerminateInstr,
}

impl PacketHolder {
    pub fn new_ipv4_from_mac(
        intf_name: &str,
        net_intf_mac: MacAddr,
        net_intf_ip: IpAddr,
        mac_src: MacAddr,
        mac_dst: MacAddr,
        packet_type: EtherType,
        ip_src: IpAddr,
        ip_dst: IpAddr,
        packet_len: usize,
    ) -> Self {
        Self {
            packet_dir: PacketRoutingDirection::Ipv4NotDetermined,
            net_intf_name: String::from(intf_name),
            net_intf_ip,
            _net_intf_mac : net_intf_mac,
            _packet_type : packet_type,
            mac_src,
            mac_dst,
            org_src_ep: Some(IpEndPoint {
                ip: ip_src,
                port: 0,
            }),
            org_dst_ep: Some(IpEndPoint {
                ip: ip_dst,
                port: 0,
            }),
            packet_len,
            payload_len: 0,
            payload_offset : 0,
            packet_buff: Vec::new(),
            fwd_src_ep: None,
            fwd_dst_ep: None,
        }
    }

    pub fn set_routing_dir(&mut self, dir: PacketRoutingDirection) {
        self.packet_dir = dir;
    }

    pub fn set_org_dst_ep(&mut self, ep: IpEndPoint) {
        self.org_dst_ep = Some(ep);
    }

    pub fn set_org_src_ep(&mut self, ep: IpEndPoint) {
        self.org_src_ep = Some(ep);
    }

    pub fn set_org_dst_ep_port(&mut self, port: u16) {
        if let Some(ref mut v) = self.org_dst_ep {
            v.port = port;
        }
    }

    pub fn set_org_src_ep_port(&mut self, port: u16) {
        if let Some(ref mut v) = self.org_src_ep {
            v.port = port;
        }
    }

    pub fn set_fwd_src_ep_port(&mut self, port: u16) -> anyhow::Result<IpEndPoint> {
        if let Some(ref mut v) = self.fwd_src_ep {
            v.port = port;
            return Ok(v.clone());
        }
        Err(anyhow!("Forward source endpoint is not defined"))
    }

    pub fn set_fwd_src_ep(&mut self, ip: IpAddr, port: u16) {
        self.fwd_src_ep = Some(IpEndPoint { ip: ip, port: port });
    }

    pub fn set_fwd_src_ep_from_ep(&mut self, ep: IpEndPoint) {
        self.fwd_src_ep = Some(ep);
    }

    pub fn set_fwd_dst_ep(&mut self, ip: IpAddr, port: u16) {
        self.fwd_dst_ep = Some(IpEndPoint { ip: ip, port: port });
    }

    pub fn set_fwd_dst_ep_from_ep(&mut self, ep: IpEndPoint) {
        self.fwd_dst_ep = Some(ep);
    }

    pub fn get_after_ipv4_header(&self) -> &[u8] {
        // Assume all is good
        // TODO: enclose return in result
        &self.packet_buff[IPV4_HEADER_LEN..self.packet_len]
    }

    // Create packet from given packet, to forward
    // It is assumed that packet origin is set prior to calling this function
    pub fn build_ipv4_udp_from(&mut self, org_packet: &PacketHolder) -> Result<bool> {
        let Some(dst_ep) = self.org_dst_ep else {
            return Err(anyhow!("Destination end point is not specified"));
        };

        if dst_ep.port == 0 {
            return Err(anyhow!("Destination port is not set"));
        }

        let Some(src_ep) = self.org_src_ep else {
            return Err(anyhow!("Source end point is not set"));
        };

        if src_ep.port == 0 {
            return Err(anyhow!("Source port is not set"));
        }

        // Build packet to forward packet to destination
        let payload = org_packet.packet_buff.as_slice().as_ref();
        let payload_len = payload.len();
        self.payload_len = payload_len;
        let total_len = IPV4_HEADER_LEN + UDP_HEADER_LEN + payload_len;
        self.packet_len = total_len;

        // create empty packet filled with zero up to total length
        self.packet_buff = vec![0u8; total_len];
        let packet_bytes: &mut [u8] = self.packet_buff.as_mut_slice();

        // Copy payload
        {
            self.payload_offset = IPV4_HEADER_LEN + UDP_HEADER_LEN;
            for i in 0..payload_len {
                packet_bytes[self.payload_offset + i] = payload[i];
            }
        }

        // Construct entire layer 3 and 4 UDP packet including IPV4 header
        {
            let mut udp_header = MutableUdpPacket::new(&mut packet_bytes[IPV4_HEADER_LEN..])
                .expect("could not create MutableUdpPacket");
            udp_header.set_source(src_ep.port);
            udp_header.set_destination(dst_ep.port);
            udp_header.set_length((UDP_HEADER_LEN + payload_len) as u16);
        }

        // Set UDP header
        {
            let src_ip = IpEndPoint::ip_as_ipv4(&src_ep.ip);
            let dst_ip = IpEndPoint::ip_as_ipv4(&dst_ep.ip);
            let slice = &mut packet_bytes[IPV4_HEADER_LEN..];
            let checksum = ipv4_checksum(
                &UdpPacket::new(slice).expect("could not create UdpPacket"),
                &src_ip,
                &dst_ip,
            );
            MutableUdpPacket::new(slice)
                .expect("could not create MutableUdpPacket")
                .set_checksum(checksum);
        }
        Ok(true)
    }

    // Print packet data
    // TODO : override fmt::Display trait for generic debug print
    pub fn print(&self) {
        let (dst_ip, dst_port) = match self.org_dst_ep {
            Some(v) => (v.ip, v.port),
            None => (IPV4_EMPTY, 0),
        };

        let (src_ip, src_port) = match self.org_src_ep {
            Some(v) => (v.ip, v.port),
            None => (IPV4_EMPTY, 0),
        };

        println!(
            "[{}]: Packet: mac {} > {}, ip {}:{} > {}:{}; payload length: {}, payload: {}",
            self.net_intf_name.as_str(),
            self.mac_src,
            self.mac_dst,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            self.payload_len,
            hex::encode(&self.packet_buff.as_slice()[self.payload_offset..]),
        );
    }
}

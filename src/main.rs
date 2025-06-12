// ----------------------------------------------------------------------------
// Copyright (c) 2025 LeoxTec https://leoxtec.com.
// Licensed under the MIT License.
// ----------------------------------------------------------------------------

//!
//! VIRTURO - Virtual Router
//!
//! Listens on defined origin interface, captures packets sent on port having
//! specific pattern in payload and forwards it to another defined end point
//! Currently only UDP packets are implemented.
//!
//! Required config.json to work
//!
//! Run with administrator privileges,
//! requires pnet crate, refer to pnet crate requirements on different OS platforms
//!
//!

use std::net::IpAddr;
use std::process::exit;
use std::str::FromStr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

//use anyhow::{anyhow, Result};
use ctrlc;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self};
use pnet::packet::ethernet::*;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{transport_channel, TransportChannelType, TransportSender};
use pnet::util::MacAddr;

use clap::Parser;

mod app_utils;
use app_utils::*;

mod app_config;
use app_config::*;

mod net_common;
use net_common::*;

mod packet_handler;
use packet_handler::*;

mod routing_handler;
use routing_handler::*;

mod pattern_handler;
//use pattern_handler::*;

mod app_cli;
use app_cli::*;

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

// Handle UDP packet, return True if matches rules and further action is required
fn handle_udp_packet(
    packet_holder: &mut PacketHolder,
    packet: &[u8],
    _raw_packet: &EthernetPacket,
    routing_data: &RoutingData,
    forward_data: PacketForwardDataShared,
) -> bool {
    let udp_packet = UdpPacket::new(packet);

    if let Some(udp) = udp_packet {
        // extract UDP payload and ports
        let payload_bin = &packet[8..];
        let dst_port = udp.get_destination();
        let src_port = udp.get_source();
        packet_holder.set_org_dst_ep_port(dst_port);
        packet_holder.set_org_src_ep_port(src_port);
        packet_holder.payload_len = payload_bin.len();
        packet_holder.packet_buff = payload_bin.to_vec();

        let show_all = routing_data.print_all_packets;
        if show_all {
            packet_holder.print();
        }

        match routing_data.route_dir {
            RoutingDirection::OriginToForward => {
                if packet_holder.mac_dst == routing_data.net_intf_mac {
                    if let Some(fwd_rule) =
                        routing_data.match_org_forward_rule(dst_port, &payload_bin)
                    {
                        println!(
                            "\n{}: Packet from origin to forward",
                            get_time_fmt(TIME_FMT)
                        );
                        if !show_all {
                            packet_holder.print();
                        }
                        // Set destination end point to forward packet to
                        {
                            let fwd_data = forward_data.read().unwrap();
                            packet_holder
                                .set_fwd_dst_ep(fwd_rule.fwd_dst_ep.ip, fwd_rule.fwd_dst_ep.port);
                            // Set source network interface and IP to forward packet from
                            // Source port will be assigned during construction of the packet
                            packet_holder.set_fwd_src_ep(fwd_data.fwd_src_ep.ip, 0);
                        }
                        packet_holder.set_routing_dir(PacketRoutingDirection::Ipv4UdpOrgToFwd);
                        return true;
                    }
                }
            }
            RoutingDirection::ForwardToOrigin => {
                // Find packet received with destination port and destination IP
                // Find one of forward destination ports as source port
                if routing_data.find_dst_forward_port(src_port) {
                    // if src_port == routing_data.fwd_port {
                    println!(
                        "\n{}: Response from Forward Server on interface {}:{}",
                        get_time_fmt(TIME_FMT),
                        packet_holder.net_intf_ip,
                        src_port
                    );

                    // Route packet to origin, if exists, first find forward entry
                    let fwd_data = forward_data.read().unwrap();
                    match fwd_data.find_entry(packet_holder.net_intf_ip, dst_port) {
                        Some(entry) => {
                            // Set origin destination from entry as forward destination
                            packet_holder.set_fwd_dst_ep_from_ep(entry.origin_src_ep.unwrap());
                            // Set origin source from entry as forward destination
                            packet_holder.set_fwd_src_ep_from_ep(entry.origin_dst_ep.unwrap());
                            packet_holder.set_routing_dir(PacketRoutingDirection::Ipv4UdpFwdToOrg);
                            println!(
                                "Origin sender was found for entry {}:{}",
                                packet_holder.net_intf_ip, dst_port
                            );
                            packet_holder.print();
                            return true;
                        }
                        None => {}
                    };
                    if !show_all {
                        packet_holder.print();
                    }
                }
            }
        }
    } else {
        println!(
            "[{}]: Malformed UDP Packet",
            packet_holder.net_intf_name.as_str()
        );
    }
    false
}

fn handle_transport_protocol(
    packet_holder: &mut PacketHolder,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
    raw_packet: &EthernetPacket,
    routing_data: &RoutingData,
    forward_data: PacketForwardDataShared,
) -> bool {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            return handle_udp_packet(
                packet_holder,
                packet,
                raw_packet,
                routing_data,
                forward_data,
            );
        }
        _ => {}
    }
    false
}

fn ethernet_frame_handle(
    intf_wrapper: &NetInterfaceWrapper,
    packet: &EthernetPacket,
    route_data: &RoutingData,
    forward_data: PacketForwardDataShared,
) {
    // Process frame according to type
    match packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let header = Ipv4Packet::new(packet.payload());
            if let Some(header) = header {
                // construct packet holder to hold all information from all the layers
                // as packet traverse between handlers
                let mut p_holder = PacketHolder::new_ipv4_from_mac(
                    &intf_wrapper.net_name,
                    route_data.net_intf_mac,
                    route_data.net_intf_ip,
                    packet.get_source(),
                    packet.get_destination(),
                    packet.get_ethertype(),
                    IpAddr::V4(header.get_source()),
                    IpAddr::V4(header.get_destination()),
                    packet.packet().len(),
                );

                if handle_transport_protocol(
                    &mut p_holder,
                    header.get_next_level_protocol(),
                    header.payload(),
                    &packet,
                    route_data,
                    forward_data,
                ) == true
                {
                    // send payload with packet holder and destination to Tx channel (waits on different thread)
                    route_data.packet_tx_channel.send(p_holder).unwrap();
                }
            }
        }
        // EtherTypes::Ipv6 => {},
        _ => {}
    };
}

// Listen to interface and capture packets of interest
fn net_interface_listen(
    intf_wrapper: &NetInterfaceWrapper,
    route_data: &RoutingData,
    forward_data: PacketForwardDataShared,
) {
    // Get data link channel
    let (_, mut rx) = match datalink::channel(&intf_wrapper.phy_intf, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    println!("Starting to listen on {}", &intf_wrapper.net_name);

    // Listen on link channel and process events
    loop {
        match rx.next() {
            Ok(packet) => {
                let forward_data_ptr = Arc::clone(&forward_data);
                // TODO check on Linux, Windows, WSL2
                if cfg!(any(target_os = "macos")) {
                    let payload_offset;
                    if intf_wrapper.phy_intf.is_loopback() {
                        // The pnet code for BPF loopback adds a zero'd out Ethernet header
                        payload_offset = 12;
                    } else {
                        payload_offset = 0;
                    }
                    // println!("loopback: {}, {}",packet.len(), hex::encode(packet));
                    if packet.len() > payload_offset {
                        let ip_packet = Ipv4Packet::new(&packet[payload_offset..]).unwrap();
                        let version = ip_packet.get_version();
                        if version == 4 {
                            // check that original packet is less than allowed 1, skip if larger
                            if packet.len() > LOOPBACK_PACKET_MAX {
                                println!(
                                    "Packet is longer {} than allowed {}, dropping",
                                    packet.len(),
                                    LOOPBACK_PACKET_MAX
                                );
                                continue;
                            }
                            // Create and fill artificial ethernet frame
                            let mut buf: [u8; MAX_ETH_PACKET] = [0u8; MAX_ETH_PACKET];
                            let mut eth_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();
                            eth_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            eth_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            eth_frame.set_ethertype(EtherTypes::Ipv4);
                            eth_frame.set_payload(&packet[payload_offset..]);
                            ethernet_frame_handle(
                                intf_wrapper,
                                &eth_frame.to_immutable(),
                                route_data,
                                forward_data_ptr,
                            );
                            continue;
                        } else if version == 6 {
                            continue;
                        }
                    }
                }
                ethernet_frame_handle(
                    intf_wrapper,
                    &EthernetPacket::new(packet).unwrap(),
                    route_data,
                    forward_data_ptr,
                );
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!(
                    "Error receiving packet on channel {} error: {}",
                    intf_wrapper.net_name, e
                );
            }
        }
    }
}

// Forward packets from one interface to another
fn packet_routing_handler(
    packet_rx: &PacketRecvChannel,
    transport_tx: &mut TransportSender,
    _routing_data: &RoutingData,
    forward_data: PacketForwardDataShared,
) {
    // get forward data for packet, as was previously detected
    loop {
        match packet_rx.recv() {
            Ok(packet) => {
                // Prepare packet according to determined packet direction
                match packet.packet_dir {
                    //
                    PacketRoutingDirection::Ipv4UdpOrgToFwd => {
                        // Prepare packet to be sent to origin
                        // Original packet is valid, create copy and send
                        let mut tx_packet = packet.clone();

                        // origin packet (src, dst ep), fwd (src, dst)
                        // tx packet:
                        //  src ep = fwd src, random port (peer port)
                        //  dst ep = fwd dst ep
                        //  fwd src, fwd port = None

                        // Saved entry:
                        // origin src ep = origin packet src, before packet is built, would be changed
                        // origin dst ep = origin packet dst, before packet
                        // fwd src ep = tx packet fwd src ep, after build packet
                        // fwd dst ep = tx packet fwd dst ep

                        let Some(org_src_ep) = packet.org_src_ep else {
                            // TODO : log error
                            continue;
                        };

                        // check if entry for origin already exists
                        let fwd_src_port = match forward_data
                            .read()
                            .unwrap()
                            .find_entry(org_src_ep.ip, org_src_ep.port)
                        {
                            // Get previously used port
                            Some(entry) => {
                                // println!("Routing entry found Entry {:?}", entry);
                                entry.fwd_src_ep.unwrap().port
                            }
                            // Set random port as forward source
                            None => {
                                IpEndPoint::generate_udp_port(PEERPORT_PORT_MIN, PEERPORT_PORT_MAX)
                            }
                        };

                        let Some(org_dst_ep) = packet.org_dst_ep else {
                            // TODO : log error
                            continue;
                        };

                        let Some(fwd_dst_ep) = packet.fwd_dst_ep else {
                            // TODO : log error
                            continue;
                        };

                        // Set forward source port
                        let fwd_src_ep = match tx_packet.set_fwd_src_ep_port(fwd_src_port) {
                            Ok(v) => v,
                            Err(_) => {
                                continue;
                            }
                        };

                        // update source port in tx_packet
                        tx_packet.set_org_src_ep(fwd_src_ep);
                        // Set destination new endpoint to tx_packet
                        tx_packet.set_org_dst_ep(fwd_dst_ep);

                        // Try building IPV4 UDP packet
                        match tx_packet.build_ipv4_udp_from(&packet) {
                            Ok(_) => {
                                let tx_udp = UdpPacket::new(&tx_packet.get_after_ipv4_header())
                                    .expect("Could not create UdpPacket to forward");
                                println!(
                                    "{} Forwarding from origin {} to {} -> {}",
                                    get_time_fmt(TIME_FMT),
                                    org_dst_ep,
                                    fwd_src_ep,
                                    fwd_dst_ep
                                );
                                // Add entry to forwarded packet
                                // key is current source ip address and peer port
                                let fwd_data = forward_data.read().unwrap();
                                fwd_data
                                    .new_entry_pair(org_src_ep, org_dst_ep, fwd_src_ep, fwd_dst_ep);
                                // fwd_data.print_entries();
                                transport_tx.send_to(tx_udp, fwd_dst_ep.ip).unwrap();
                                tx_packet.print();
                            }
                            Err(e) => {
                                println!("{:?}", e.to_string());
                            }
                        }
                    }
                    PacketRoutingDirection::Ipv4UdpFwdToOrg => {
                        // Prepare packet to be sent to origin
                        let mut tx_packet = packet.clone();

                        // Assign Origin destination forward source and destinations
                        // Assume endpoints were set by processing function before sending to here
                        // let Some(org_src_ep) = packet.org_src_ep else {
                        //     continue;
                        // };
                        let Some(org_dst_ep) = packet.org_dst_ep else {
                            continue;
                        };
                        let Some(fwd_src_ep) = packet.fwd_src_ep else {
                            continue;
                        };
                        let Some(fwd_dst_ep) = packet.fwd_dst_ep else {
                            continue;
                        };

                        tx_packet.set_org_src_ep(fwd_src_ep);
                        tx_packet.set_org_dst_ep(fwd_dst_ep);

                        match tx_packet.build_ipv4_udp_from(&packet) {
                            Ok(true) => {
                                let tx_udp = UdpPacket::new(&tx_packet.get_after_ipv4_header())
                                    .expect("Could not create UdpPacket to origin");
                                println!(
                                    "{} Routing packet from forward {} to origin {}",
                                    get_time_fmt(TIME_FMT),
                                    org_dst_ep,
                                    fwd_dst_ep
                                );
                                // Add entry to forwarded packet
                                // key is current source ip address and peer port
                                transport_tx.send_to(tx_udp, fwd_dst_ep.ip).unwrap();
                                tx_packet.print();
                            }
                            Ok(false) => {
                                println!("Failed to build ipv4 udp packet for Ipv4UdpFwdToOrg");
                            }
                            Err(e) => {
                                println!("{:?}", e.to_string());
                            }
                        };

                        continue;
                    }
                    _ => {
                        continue;
                    }
                };
            }
            Err(_) => {
                panic!("Error received on forward channel");
            }
        }
    }
}

fn routing_data_cleanup(forward_data: PacketForwardDataShared, ttl_sec: u32) {
    loop {
        thread::sleep(Duration::from_secs(1));
        // Clear old entries, older than provided threshold
        let entries_to_remove: Vec<String>;
        {
            let forward_data_ptr = forward_data.read().unwrap();
            entries_to_remove = forward_data_ptr.find_old_entries(ttl_sec);
        }

        if entries_to_remove.len() > 0 {
            let forward_data_ptr = forward_data.write().unwrap();
            let _deleted = forward_data_ptr.remove_entries_by_list(&entries_to_remove);
        }
    }
}

fn main() {
    //let _ = env::set_var("RUST_BACKTRACE", "1");
    println!("Virturo - Virtual Router v{APP_VERSION}\n");
    let cli_params = CliParams::parse();

    // Check if only listing of interfaces is required
    if cli_params.list == true {
        list_net_interfaces();
        exit(0);
    }

    let cnf_file = cli_params.config;
    println!("Using configuration file: {cnf_file}");
    let cnf_sections = config_load(cnf_file.as_str()).unwrap();

    let cnf_fwd_rules =
        config_parse_fwd_rules_section(&cnf_sections, CNF_FORWARD_RULES_SECTION).unwrap();
    if cnf_fwd_rules.len() == 0 {
        println!("No forward rules are defined...Exiting.");
        exit(0);
    }

    let cnf_gen_settings =
        match config_parse_cnf_settings_section(&cnf_sections, CNF_GEN_SETTINGS_SECTION) {
            Ok(v) => v,
            Err(_) => {
                let v = CnfGenSettings::default();
                println!(
                    "General settings section was not found using defaults {:?}",
                    v
                );
                v
            }
        };

    let entry_ttl_sec = cnf_gen_settings.fwd_entry_ttl_sec;

    // currently use single rule only
    let fwd_rule = &cnf_fwd_rules[0];
    let net_intf_name: &str = &fwd_rule.org_interface.as_str();
    // get origin and forward interfaces from rule
    let org_net_intf = net_interface_get(&fwd_rule.org_interface).expect(&String::from(format!(
        "Could not find requested origin interface {}",
        net_intf_name
    )));

    let net_intf_name: &str = &fwd_rule.fwd_interface.as_str();
    let fwd_net_intf = net_interface_get(&fwd_rule.fwd_interface).expect(&String::from(format!(
        "Could not find requested forward interface {}",
        net_intf_name
    )));

    // Channel to forward captured and matched data
    let (tx_fwd, rx_fwd): (PacketSenderChannel, PacketRecvChannel) = channel();

    // Create persistent routing data with break down interface
    let mut org_route_data = RoutingData::new(
        tx_fwd.clone(),
        RoutingDirection::OriginToForward,
        org_net_intf.net_intf_ip,
        org_net_intf.net_intf_mac,
        fwd_rule.org_dst_port,
        false,
    );
    org_route_data
        .build_forward_rules(&fwd_rule.org_patterns)
        .unwrap();

    // validate forward rules
    let fwd_dst_ip = IpAddr::from_str(&fwd_rule.org_patterns[0].fwd_dst_ip)
        .expect("Invalid forward destination IP address");

    let fwd_dst_port = fwd_rule.org_patterns[0].fwd_dst_port;
    // Create forward data structure within shared reference
    let fwd_data = PacketForwardData::new(fwd_dst_ip, fwd_dst_port, fwd_net_intf.net_intf_ip);
    let fwd_data_arc = Arc::new(RwLock::new(fwd_data));
    println!(
        "Origin Interface: mac {}, ip {} ",
        org_route_data.net_intf_mac, org_route_data.net_intf_ip
    );

    // Setup relay interface, can be same or different from inbound
    let mut relay_route_data = RoutingData::new(
        tx_fwd.clone(),
        RoutingDirection::ForwardToOrigin,
        fwd_net_intf.net_intf_ip,
        fwd_net_intf.net_intf_mac,
        0,
        false,
    );
    relay_route_data
        .build_forward_ports(&fwd_rule.org_patterns)
        .unwrap();

    println!(
        "Relay Interface: mac {}, ip {} ",
        relay_route_data.net_intf_mac, relay_route_data.net_intf_ip
    );

    // Spawn listen thread for forwarding rx packet
    let route_data_ch = org_route_data.clone();

    // Create transport channel for layer4 (UDP) forwarding
    let (mut tx_transport, _) = transport_channel(
        TRANSPORT_UDP_PACKET_MAX,
        TransportChannelType::Layer4(Ipv4(IpNextHeaderProtocols::Udp)),
    )
    .expect("Cannot create transport layer");

    // Setup CTRL-C handler, receive channel waits for signal to exit application
    let (app_stop_tx, app_stop_rx): (Sender<()>, Receiver<()>) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || {
        app_stop_tx
            .send(())
            .expect("Could not send signal on channel.")
    })
    .expect("Error setting Ctrl-C handler");

    let fwd_data_arc_h = Arc::clone(&fwd_data_arc);
    let _fwd_thr = thread::spawn(move || {
        packet_routing_handler(&rx_fwd, &mut tx_transport, &route_data_ch, fwd_data_arc_h);
    });

    // listen on origin interface
    let fwd_data_arc_p1 = Arc::clone(&fwd_data_arc);
    let _net_main_thr = thread::spawn(move || {
        net_interface_listen(&org_net_intf, &org_route_data, fwd_data_arc_p1);
    });

    // Listen on relayed interface
    let fwd_data_arc_p2 = Arc::clone(&fwd_data_arc);
    let _net_relay_thr = thread::spawn(move || {
        net_interface_listen(&fwd_net_intf, &relay_route_data, fwd_data_arc_p2);
    });

    // Management thread to clean up routing tables after timeout
    let fwd_data_arc_p3 = Arc::clone(&fwd_data_arc);
    let _clean_routing_thr = thread::spawn(move || {
        routing_data_cleanup(fwd_data_arc_p3, entry_ttl_sec as u32);
    });

    app_stop_rx
        .recv()
        .expect("Could not receive from stop channel.");

    // TODO : handle proper thread cancellations
    println!("Exiting...");
}

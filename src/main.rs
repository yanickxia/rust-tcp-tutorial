extern crate pnet;

use std::env;

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;

use crate::tcp::process;

mod ip;
mod tcp;

const LISTENING_PORT: u16 = 10023;

fn main() {
    let interface_name = env::args().nth(1).unwrap();
    let interface_names_match =
        |iface: &NetworkInterface| iface.name == interface_name;

    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let payload_offset;
                if cfg!(any(target_os = "macos", target_os = "ios"))
                    && interface.is_up()
                    && !interface.is_broadcast()
                    && ((!interface.is_loopback() && interface.is_point_to_point())
                    || interface.is_loopback())
                {
                    if interface.is_loopback() {
                        // The pnet code for BPF loopback adds a zero'd out Ethernet header
                        payload_offset = 14;
                    } else {
                        // Maybe is TUN interface
                        payload_offset = 0;
                    }
                    if packet.len() > payload_offset && ip::IPv4::is_tcp_ip(&packet[payload_offset..]) {
                        let ipv4_packet = ip::IPv4::new(&packet[payload_offset..]);
                        let tcp_packet = tcp::TCP::new(ipv4_packet.data.as_slice());

                        if tcp_packet.header.destination_port != LISTENING_PORT {
                            continue;
                        }

                        // println!("Got Tcp Ip Package From {}:{} To {}:{} Data Len {}",
                        //          ipv4_packet.header.source(),
                        //          tcp_packet.header.source_port,
                        //          ipv4_packet.header.destination(),
                        //          tcp_packet.header.destination_port,
                        //          tcp_packet.data.len());
                        match process(ipv4_packet) {
                            Some(mut packet) => {
                                packet.checksum();
                                let bytes = packet.to_bytes();
                                let xxx = hex::encode(bytes.as_slice());
                                tx.send_to(bytes.as_slice(), Option::None);
                            }
                            None => {}
                        }
                    }
                }
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}


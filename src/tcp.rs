use std::collections::HashMap;
use std::io::{Cursor, Write};

use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use lazy_static::lazy_static;
use rand::random;

use crate::ip::IPv4;

lazy_static! {
    static ref HASHMAP: HashMap<u128, TCPCurState> = {
        let mut m = HashMap::new();
        m
    };
}

pub fn process(packet: IPv4) -> Option<IPv4> {
    let tcp_packet = TCP::new(packet.data.as_slice());

    let unique = unique(packet.header.destination_address,
                        tcp_packet.header.source_port,
                        packet.header.destination_address,
                        tcp_packet.header.destination_port);
    let connections = &HASHMAP;
    return if connections.contains_key(&unique) {
        process_established()
    } else {
        process_new(packet, tcp_packet)
    };
}

fn process_established() -> Option<IPv4> {
    return Option::None;
}

fn process_new(ip_packet: IPv4, tcp_packet: TCP) -> Option<IPv4> {
    // must be syn packet
    if !tcp_packet.header.is_syn() {
        return Option::None;
    }
    let ack_seq = tcp_packet.header.sequence_number + 1;
    let seq: u32 = random::<u32>() % 2000;

    let mut replay_packet = TCP::replay(&tcp_packet);
    replay_packet.header.sequence_number = seq;
    replay_packet.header.acknowledgment_number = ack_seq;
    replay_packet.header.mark_ack();
    replay_packet.header.mark_syn();

    let mut wtr = vec![];
    wtr.write_u32::<BigEndian>(ip_packet.header.source_address);
    wtr.write_u32::<BigEndian>(ip_packet.header.destination_address);
    wtr.write_u8(0);
    wtr.write_u8(0x06);
    wtr.write_u16::<BigEndian>(0x0014);
    replay_packet.checksum(wtr.as_slice());

    let mut ip_replay = IPv4::replay(&ip_packet);
    ip_replay.data.write(replay_packet.to_bytes().as_slice());

    Option::from(ip_replay)
}

fn unique(source_address: u32, source_port: u16, destination_address: u32, destination_port: u16) -> u128 {
    let mut unique: u128 = (source_address as u128) << 96;
    unique = unique & ((source_port as u128) << 64);
    unique = unique & ((destination_address as u128) << 32);
    unique = unique & destination_port as u128;
    return unique;
}

pub enum TCPEnum {
    Closed,
    Listen,
    SynRcvd,
    Established,
    FinWait1,
    CloseWait,
    FinWait2,
    LastAck,
    Closing,
    TimeWait,
}

pub struct TCPCurState {
    pub unread: Vec<u8>
}

pub struct TCPHeader {
    // source port, 16 bit, index 0-1
    pub source_port: u16,
    // Destination port, 16 bit, index 2-3
    pub destination_port: u16,
    // Sequence Number , 32 bit, index 4 - 7
    pub sequence_number: u32,
    // Acknowledgment Number, 32 bit, index 8 - 11
    pub acknowledgment_number: u32,
    // Data offset, 4 bit, index 12
    pub offset: u8,
    // reserved, 6bit, index 13
    pub reserved: u8,
    // flags, 6bit, index 14
    pub flags: u8,
    // windows, 16bit, index 15
    pub windows: u16,
    // checksum, 16bit, index 17
    pub checksum: u16,
    // Urgent Pointer, 16 bit, index 21
    pub urgent_pointer: u16,
    // Options len
    // Options data
}

impl TCPHeader {
    pub fn is_urg(&self) -> bool {
        self.flags & 0b100000 != 0
    }

    pub fn is_ack(&self) -> bool {
        self.flags & 0b010000 != 0
    }

    pub fn is_psh(&self) -> bool {
        self.flags & 0b001000 != 0
    }

    pub fn is_rst(&self) -> bool {
        self.flags & 0b000100 != 0
    }

    pub fn is_syn(&self) -> bool {
        self.flags & 0b000010 != 0
    }

    pub fn is_fin(&self) -> bool {
        self.flags & 0b000001 != 0
    }

    pub fn mark_ack(&mut self) {
        self.flags = self.flags | 0b010000;
    }

    pub fn mark_syn(&mut self) {
        self.flags = self.flags | 0b000010;
    }
}

pub struct TCP {
    // tcp header
    pub header: TCPHeader,
    // tcp data
    pub data: Vec<u8>,
}


impl TCP {
    pub fn new(packet: &[u8]) -> TCP {
        let offset = packet[12] >> 4;
        return TCP {
            header: TCPHeader {
                source_port: BigEndian::read_u16(packet),
                destination_port: BigEndian::read_u16(&packet[2..]),
                sequence_number: BigEndian::read_u32(&packet[4..]),
                acknowledgment_number: BigEndian::read_u32(&packet[8..]),
                offset,
                reserved: (BigEndian::read_u16(&packet[12..]) << 4 >> 10) as u8,
                flags: packet[13] << 2 >> 2,
                windows: BigEndian::read_u16(&packet[14..]),
                checksum: BigEndian::read_u16(&packet[16..]),
                urgent_pointer: BigEndian::read_u16(&packet[18..]),
            },
            data: Vec::from(&packet[(offset as usize) * 4..]),
        };
    }

    pub fn replay(input: &TCP) -> TCP {
        TCP {
            header: TCPHeader {
                source_port: input.header.destination_port,
                destination_port: input.header.source_port,
                sequence_number: 0,
                acknowledgment_number: 0,
                offset: 5,
                reserved: 0,
                flags: 0,
                windows: input.header.windows,
                checksum: 0,
                urgent_pointer: 0,
            },
            data: vec![],
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut combind = self.header.offset as u16;
        combind = combind << 12;
        combind = combind | ((self.header.reserved as u16) << 6);
        combind = combind | (self.header.flags as u16);

        let mut wtr = vec![];
        wtr.write_u16::<BigEndian>(self.header.source_port);
        wtr.write_u16::<BigEndian>(self.header.destination_port);
        wtr.write_u32::<BigEndian>(self.header.sequence_number);
        wtr.write_u32::<BigEndian>(self.header.acknowledgment_number);
        wtr.write_u16::<BigEndian>(combind);
        wtr.write_u16::<BigEndian>(self.header.windows);
        wtr.write_u16::<BigEndian>(self.header.checksum);
        wtr.write_u16::<BigEndian>(self.header.urgent_pointer);
        wtr.write(self.data.as_slice());
        wtr
    }

    pub fn checksum(&mut self, pseudo_header: &[u8]) {
        let mut bytes = self.to_bytes();
        let mut wtr = vec![];
        wtr.write(pseudo_header);
        wtr.write(bytes.as_slice());

        if wtr.len() % 2 != 0 {
            wtr.write_u8(0);
        }

        let mut rdr = Cursor::new(wtr);
        let mut sum: u32 = 0;
        loop {
            match rdr.read_u16::<BigEndian>() {
                Ok(data) => {
                    sum += (data as u32);
                }
                Err(_) => {
                    break;
                }
            }
        }

        let mut rm = sum / 0xFFFF;
        while rm != 0 {
            sum = (sum % 0x10000) + rm;
            rm = sum / 0xFFFF;
        }


        self.header.checksum = (sum as u16) ^ (0xFFFF);
    }
}


#[cfg(test)]
mod test {
    use super::*;

    extern crate hex;

    #[test]
    pub fn test_parse_tcp() {
        let hex_data = hex::decode("e67ddf9817e0b77ed8615529801801f52b2300000101080a36f9392c016de81f263cdb224dcc9a4b4c2191ecb4c43c0a3daeb61233ee4af155a60c9dcac70fcebe0fca8964908c1c5f5073c50b0522eb");
        let tcp = TCP::new(hex_data.unwrap().as_slice());
        assert_eq!(59005, tcp.header.source_port);
        assert_eq!(57240, tcp.header.destination_port);
        assert_eq!(400603006, tcp.header.sequence_number);
        assert_eq!(3630257449, tcp.header.acknowledgment_number);
        assert_eq!(501, tcp.header.windows);

        assert!(tcp.header.is_psh());
        assert!(tcp.header.is_ack());
        assert!(!tcp.header.is_fin());
        assert!(!tcp.header.is_rst());
        assert!(!tcp.header.is_syn());
        assert!(!tcp.header.is_urg());


        let data = hex::decode("263cdb224dcc9a4b4c2191ecb4c43c0a3daeb61233ee4af155a60c9dcac70fcebe0fca8964908c1c5f5073c50b0522eb");
        assert_eq!(data.unwrap().as_slice(), tcp.data.as_slice());
    }

    #[test]
    pub fn test_check_sum() {
        let hex_data = hex::decode("3d937a86c0a8006800060014");

        let mut tcp = TCP {
            header: TCPHeader {
                source_port: 0x0050,
                destination_port: 51362,
                sequence_number: 743001934,
                acknowledgment_number: 3828516201,
                offset: 5,
                reserved: 0,
                flags: 0b010000,
                windows: 22,
                checksum: 0,
                urgent_pointer: 0,
            },
            data: vec![],
        };

        tcp.checksum(hex_data.unwrap().as_slice());

        assert_eq!(0x0000886e, tcp.header.checksum);
    }
}
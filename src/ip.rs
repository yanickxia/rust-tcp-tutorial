extern crate byteorder;

use std::fs::read;
use std::net::Ipv4Addr;

use byteorder::{BigEndian, ByteOrder};

pub struct IPv4Header {
    // internet header field, 4bit , index 0
    pub version: u8,
    // internet header field Internet Header Length, 4bit, index 0
    pub ihl: u8,
    // Type of Service, 8bit, index 1
    pub toc: u8,
    // total length, 16bit, index 2-3
    pub len: u16,
    // Identification, 16bit, index 4-5
    pub identification: u16,
    // flag, 3bit index 6
    pub flags: u8,
    // Fragment offset, 13 bit, index 6 - 7
    pub offset: u16,
    // ttl, 8bit, index 8
    pub ttl: u8,
    // Protocol, 8bit, index 9
    pub protocol: u8,
    // checksum, index 10 - 11
    pub checksum: u16,
    // Source Address, 32 bit, index 12,13,14,15
    pub source_address: u32,
    // Destination Address, 32 bit, index 16,17,18,19
    pub destination_address: u32,
    // Options,
    pub options_len: u8,
    pub options_buffer: Vec<u8>,
}

impl IPv4Header {
    pub fn source(&self) -> Ipv4Addr {
        return Ipv4Addr::from(self.source_address);
    }

    pub fn destination(&self) -> Ipv4Addr {
        return Ipv4Addr::from(self.destination_address);
    }
}


pub struct IPv4 {
    // header
    pub header: IPv4Header,
    // Data
    pub data: Vec<u8>,
}


impl IPv4 {
    pub fn new(packet: &[u8]) -> IPv4 {
        let len = BigEndian::read_u16(&packet[2..]);
        let ihl = packet[0] << 4 >> 4;
        return IPv4 {
            header: IPv4Header {
                version: packet[0] >> 4,
                ihl,
                toc: packet[1],
                len,
                identification: BigEndian::read_u16(&packet[4..]),
                flags: packet[6] >> 5,
                offset: BigEndian::read_u16(&packet[6..]) << 3 >> 3,
                ttl: packet[8],
                protocol: packet[9],
                checksum: BigEndian::read_u16(&packet[10..]),
                source_address: BigEndian::read_u32(&packet[12..]),
                destination_address: BigEndian::read_u32(&packet[16..]),
                options_len: 0, // not parsed
                options_buffer: vec![],
            },
            data: Vec::from(&packet[(ihl as usize) * 4..len as usize]),
        };
    }

    pub fn is_tcp_ip(packet: &[u8]) -> bool {
        if packet.len() < 10 {
            return false;
        }

        let version = packet[0] >> 4;
        let protocol = packet[9];
        return version == 4 && protocol == 6;
    }
}


#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;

    extern crate hex;

    #[test]
    pub fn test_is_tcp_ip() {
        let hex_data = hex::decode("45000034000040004006f023c0a80d1f783504a4df98e67dd861552917e0b7ae801007fff3ac00000101080a016dfbad36f9392c");
        assert!(IPv4::is_tcp_ip(hex_data.unwrap().as_slice()));
    }

    #[test]
    pub fn test_parse_ip_packet() {
        let hex_data = hex::decode("45280064bb39400034064092783504a4c0a80d1fe67ddf9817e0b77ed8615529801801f52b2300000101080a36f9392c016de81f263cdb224dcc9a4b4c2191ecb4c43c0a3daeb61233ee4af155a60c9dcac70fcebe0fca8964908c1c5f5073c50b0522eb");
        let ipv4 = IPv4::new(hex_data.unwrap().as_slice());
        assert_eq!(4, ipv4.header.version);
        assert_eq!(6, ipv4.header.protocol);
        assert_eq!(Ipv4Addr::from_str("120.53.4.164").unwrap(), ipv4.header.source());
        assert_eq!(Ipv4Addr::from_str("192.168.13.31").unwrap(), ipv4.header.destination());

        let data = hex::decode("e67ddf9817e0b77ed8615529801801f52b2300000101080a36f9392c016de81f263cdb224dcc9a4b4c2191ecb4c43c0a3daeb61233ee4af155a60c9dcac70fcebe0fca8964908c1c5f5073c50b0522eb");
        assert_eq!(data.unwrap().as_slice(), ipv4.data.as_slice());
    }
}

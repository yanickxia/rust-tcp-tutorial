use std::collections::HashMap;

use byteorder::{BigEndian, ByteOrder};
use lazy_static::lazy_static;

lazy_static! {
    static ref HASHMAP: HashMap<u64, TCPState> = {
        let mut m = HashMap::new();
        m
    };
}

pub fn process(tcp_packet: TCP) {}

pub struct TCPState {
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
}
#![feature(test)]
extern crate test;

extern crate pktparse;
extern crate sniffglue;

pub use sniffglue::*;

#[cfg(test)]
mod tests {
    use super::*;
    use test::Bencher;

    const HTML: [u8; 390] = [
        32, 32, 32, 32, 32, 32, 32, 112, 97, 100, 100, 105, 110, 103, 58, 32, 49, 101, 109, 59, 10,
        32, 32, 32, 32, 32, 32, 32, 32, 125, 10, 32, 32, 32, 32, 125, 10, 32, 32, 32, 32, 60, 47,
        115, 116, 121, 108, 101, 62, 32, 32, 32, 32, 10, 60, 47, 104, 101, 97, 100, 62, 10, 10, 60,
        98, 111, 100, 121, 62, 10, 60, 100, 105, 118, 62, 10, 32, 32, 32, 32, 60, 104, 49, 62, 69,
        120, 97, 109, 112, 108, 101, 32, 68, 111, 109, 97, 105, 110, 60, 47, 104, 49, 62, 10, 32,
        32, 32, 32, 60, 112, 62, 84, 104, 105, 115, 32, 100, 111, 109, 97, 105, 110, 32, 105, 115,
        32, 101, 115, 116, 97, 98, 108, 105, 115, 104, 101, 100, 32, 116, 111, 32, 98, 101, 32,
        117, 115, 101, 100, 32, 102, 111, 114, 32, 105, 108, 108, 117, 115, 116, 114, 97, 116, 105,
        118, 101, 32, 101, 120, 97, 109, 112, 108, 101, 115, 32, 105, 110, 32, 100, 111, 99, 117,
        109, 101, 110, 116, 115, 46, 32, 89, 111, 117, 32, 109, 97, 121, 32, 117, 115, 101, 32,
        116, 104, 105, 115, 10, 32, 32, 32, 32, 100, 111, 109, 97, 105, 110, 32, 105, 110, 32, 101,
        120, 97, 109, 112, 108, 101, 115, 32, 119, 105, 116, 104, 111, 117, 116, 32, 112, 114, 105,
        111, 114, 32, 99, 111, 111, 114, 100, 105, 110, 97, 116, 105, 111, 110, 32, 111, 114, 32,
        97, 115, 107, 105, 110, 103, 32, 102, 111, 114, 32, 112, 101, 114, 109, 105, 115, 115, 105,
        111, 110, 46, 60, 47, 112, 62, 10, 32, 32, 32, 32, 60, 112, 62, 60, 97, 32, 104, 114, 101,
        102, 61, 34, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 105, 97, 110, 97, 46, 111,
        114, 103, 47, 100, 111, 109, 97, 105, 110, 115, 47, 101, 120, 97, 109, 112, 108, 101, 34,
        62, 77, 111, 114, 101, 32, 105, 110, 102, 111, 114, 109, 97, 116, 105, 111, 110, 46, 46,
        46, 60, 47, 97, 62, 60, 47, 112, 62, 10, 60, 47, 100, 105, 118, 62, 10, 60, 47, 98, 111,
        100, 121, 62, 10, 60, 47, 104, 116, 109, 108, 62, 10,
    ];

    #[test]
    fn tcp() {
        use structs::ether::Ether::IPv4;
        use structs::ipv4::IPv4::TCP;
        use structs::raw::Raw::Ether;
        use structs::tcp::TCP::Text;

        use pktparse::ethernet::{EtherType, EthernetFrame, MacAddress};
        use pktparse::ipv4::{IPv4Header, IPv4Protocol};
        use pktparse::tcp::TcpHeader;

        let mut pkt = Vec::new();
        pkt.extend(
            [
                0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 8, 0, 69,
                0, 1, 186, 78, 105, 64, 0, 55, 6, 251, 115, 93, 184, 216, 34, 192, 168, 44, 55, 0,
                80, 142, 158, 133, 72, 141, 7, 64, 115, 177, 1, 128, 24, 1, 27, 200, 121, 0, 0, 1,
                1, 8, 10, 59, 135, 198, 7, 93, 127, 194, 19,
            ]
            .iter(),
        );
        pkt.extend(HTML.iter());

        let expected = Ok(Ether(
            EthernetFrame {
                source_mac: MacAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
                dest_mac: MacAddress([0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc]),
                ethertype: EtherType::IPv4,
            },
            IPv4(
                IPv4Header {
                    version: 4,
                    ihl: 20,
                    tos: 0,
                    length: 442,
                    id: 20073,
                    flags: 2,
                    fragment_offset: 0,
                    ttl: 55,
                    protocol: IPv4Protocol::TCP,
                    chksum: 64371,
                    source_addr: "93.184.216.34".parse().unwrap(),
                    dest_addr: "192.168.44.55".parse().unwrap(),
                },
                TCP(
                    TcpHeader {
                        source_port: 80,
                        dest_port: 36510,
                        sequence_no: 2236124423,
                        ack_no: 1081323777,
                        data_offset: 8,
                        reserved: 0,
                        flag_urg: false,
                        flag_ack: true,
                        flag_psh: true,
                        flag_rst: false,
                        flag_syn: false,
                        flag_fin: false,
                        window: 283,
                        checksum: 51321,
                        urgent_pointer: 0,
                        options: None,
                    },
                    Text(String::from_utf8(HTML.to_vec()).unwrap()),
                ),
            ),
        ));

        let x = centrifuge::parse_eth(&pkt);
        assert_eq!(expected, x);
    }

    #[bench]
    fn bench_empty(b: &mut Bencher) {
        b.iter(|| {
            centrifuge::parse_eth(&[]).ok();
        });
    }

    #[bench]
    fn bench(b: &mut Bencher) {
        let mut pkt = Vec::new();
        pkt.extend(
            [
                0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 8, 0, 69,
                0, 1, 186, 78, 105, 64, 0, 55, 6, 251, 115, 93, 184, 216, 34, 192, 168, 44, 55, 0,
                80, 142, 158, 133, 72, 141, 7, 64, 115, 177, 1, 128, 24, 1, 27, 200, 121, 0, 0, 1,
                1, 8, 10, 59, 135, 198, 7, 93, 127, 194, 19,
            ]
            .iter(),
        );
        pkt.extend(HTML.iter());

        b.iter(|| {
            centrifuge::parse_eth(&pkt).ok();
        });
    }
}

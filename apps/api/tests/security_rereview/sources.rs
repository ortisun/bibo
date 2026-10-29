//! The grouping of connections and requests by source (API-6, API-9).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use factory_api::limits::source_of;

/// An IPv4 address, its IPv4-mapped form and its form through a dual-stack listener are one source.
#[test]
fn held_an_ipv4_peer_is_one_source_in_both_notations() {
    let v4 = Ipv4Addr::new(203, 0, 113, 9);
    let mapped = IpAddr::V6(v4.to_ipv6_mapped());
    assert_eq!(source_of(IpAddr::V4(v4)), source_of(mapped));
    // Two clients of one /48 are one source, whatever their /64 is; two clients of two /48s are two.
    let a: Ipv6Addr = "2001:db8:1:2::1".parse().expect("an address");
    let b: Ipv6Addr = "2001:db8:1:2:ffff::7".parse().expect("an address");
    let c: Ipv6Addr = "2001:db8:1:3::1".parse().expect("an address");
    let d: Ipv6Addr = "2001:db8:2:2::1".parse().expect("an address");
    assert_eq!(source_of(IpAddr::V6(a)), source_of(IpAddr::V6(b)));
    assert_eq!(source_of(IpAddr::V6(a)), source_of(IpAddr::V6(c)));
    assert_ne!(source_of(IpAddr::V6(a)), source_of(IpAddr::V6(d)));
}

/// RR-10 (fixed: the source is the /48). The source of an IPv6 client was its /64, "the smallest block a
/// provider hands to one subscriber". Providers hand a /56 (256 blocks) or a /48 (65,536 blocks) to a subscriber, and a
/// cloud tenant routinely holds a /48 or a /56. Such a client is 256 or 65,536 sources: the per-source
/// connection share (a sixteenth of the total by default) and the per-source request rate do not bind
/// it. Sixteen /64 blocks of one /56 fill every connection slot of a default server.
#[test]
fn rr_10_the_blocks_of_one_56_are_not_hundreds_of_sources() {
    let sources: std::collections::BTreeSet<IpAddr> = (0_u16..256)
        .map(|block| {
            let address = Ipv6Addr::new(0x2001, 0xdb8, 0x1, block, 0, 0, 0, 1);
            source_of(IpAddr::V6(address))
        })
        .collect();
    // The default share is a sixteenth of the connections: a client that is 16 sources fills all of them.
    assert!(
        sources.len() < 16,
        "the 256 blocks of one /56 are {} sources",
        sources.len()
    );
}

/// The whole of a /48 is one source: 65,536 blocks of /64 are not 65,536 sources.
#[test]
fn rr_10_the_blocks_of_one_48_are_one_source() {
    let sources: std::collections::BTreeSet<IpAddr> = (0_u32..=0xffff)
        .step_by(97)
        .map(|block| {
            let block = u16::try_from(block).expect("a segment");
            source_of(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0xdb8, 0x1, block, 0, block, 0, 1,
            )))
        })
        .collect();
    assert_eq!(sources.len(), 1, "{sources:?}");
}

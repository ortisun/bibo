//! The grouping of connections and requests by source (API-6, API-9).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use factory_api::limits::source_of;

/// An IPv4 address, its IPv4-mapped form and its form through a dual-stack listener are one source.
#[test]
fn held_an_ipv4_peer_is_one_source_in_both_notations() {
    let v4 = Ipv4Addr::new(203, 0, 113, 9);
    let mapped = IpAddr::V6(v4.to_ipv6_mapped());
    assert_eq!(source_of(IpAddr::V4(v4)), source_of(mapped));
    // Two clients of one /64 are one source, two clients of two /64s are two.
    let a: Ipv6Addr = "2001:db8:1:2::1".parse().expect("an address");
    let b: Ipv6Addr = "2001:db8:1:2:ffff::7".parse().expect("an address");
    let c: Ipv6Addr = "2001:db8:1:3::1".parse().expect("an address");
    assert_eq!(source_of(IpAddr::V6(a)), source_of(IpAddr::V6(b)));
    assert_ne!(source_of(IpAddr::V6(a)), source_of(IpAddr::V6(c)));
}

/// RR-10. The source of an IPv6 client is its /64, "the smallest block a provider hands to one
/// subscriber". Providers hand a /56 (256 blocks) or a /48 (65,536 blocks) to a subscriber, and a
/// cloud tenant routinely holds a /48 or a /56. Such a client is 256 or 65,536 sources: the per-source
/// connection share (a sixteenth of the total by default) and the per-source request rate do not bind
/// it. Sixteen /64 blocks of one /56 fill every connection slot of a default server.
#[test]
#[ignore = "confirmed defect RR-10: a client with a /56 is 256 sources for the connection cap and the rate limit; cargo test -p factory-api --test security_rereview --locked -- --ignored rr_10 --exact"]
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

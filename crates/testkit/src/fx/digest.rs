//! Digests and message authentication codes for the fake GitHub server.
//!
//! GitHub signs a webhook with HMAC-SHA256 in `X-Hub-Signature-256` and, for older receivers,
//! with HMAC-SHA1 in `X-Hub-Signature`. The fake server has to produce both, because one of the
//! attacks in the catalog (NT-WH-02) sends the SHA-1 header alone.
//!
//! * SHA-256 comes from `factory_domain::values::Sha256Digest`, the one SHA-256 in the project.
//!   HMAC is built on top of it here (RFC 2104).
//! * SHA-1 is written out below. It exists only to forge the legacy header and is never used to
//!   protect anything.
//!
//! Both are checked against published vectors (FIPS 180, RFC 2202, RFC 4231).

use factory_domain::values::Sha256Digest;

use super::encoding::hex_decode;

const SHA256_BLOCK: usize = 64;
const SHA1_BLOCK: usize = 64;

/// SHA-256 of `input`.
#[must_use]
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let digest = Sha256Digest::of(input);
    let bytes = hex_decode(digest.hex()).expect("a SHA-256 digest is 64 hex characters");
    bytes.try_into().expect("a SHA-256 digest is 32 bytes long")
}

/// HMAC-SHA256 of `message` under `key` (RFC 2104).
#[must_use]
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    hmac(key, message, SHA256_BLOCK, |data| sha256(data).to_vec())
        .try_into()
        .expect("HMAC-SHA256 is 32 bytes long")
}

/// SHA-1 of `input` (FIPS 180-4). Only for the legacy webhook header.
#[must_use]
pub fn sha1(input: &[u8]) -> [u8; 20] {
    let mut state: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let mut message = input.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&((input.len() as u64) * 8).to_be_bytes());
    for block in message.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for (slot, word) in w.iter_mut().zip(block.as_chunks::<4>().0) {
            *slot = u32::from_be_bytes(*word);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = state;
        for (i, &word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e]) {
            *slot = slot.wrapping_add(value);
        }
    }
    let mut out = [0u8; 20];
    for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(state) {
        *chunk = word.to_be_bytes();
    }
    out
}

/// HMAC-SHA1 of `message` under `key`. Only for the legacy webhook header.
#[must_use]
pub fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    hmac(key, message, SHA1_BLOCK, |data| sha1(data).to_vec())
        .try_into()
        .expect("HMAC-SHA1 is 20 bytes long")
}

fn hmac(key: &[u8], message: &[u8], block: usize, hash: impl Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let mut key_block = if key.len() > block {
        hash(key)
    } else {
        key.to_vec()
    };
    key_block.resize(block, 0);
    let mut inner: Vec<u8> = key_block.iter().map(|b| b ^ 0x36).collect();
    inner.extend_from_slice(message);
    let mut outer: Vec<u8> = key_block.iter().map(|b| b ^ 0x5c).collect();
    outer.extend_from_slice(&hash(&inner));
    hash(&outer)
}

/// Compares two byte strings in time that depends only on the length of the longer one.
///
/// The fake server's reference verifier uses this and never `==`, so it is the same shape as the
/// code under test must be (static check ST-02). Strings of different length are never equal.
#[must_use]
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let longest = left.len().max(right.len());
    let mut difference = u8::from(left.len() != right.len());
    for i in 0..longest {
        let a = left.get(i).copied().unwrap_or(0);
        let b = right.get(i).copied().unwrap_or(0);
        difference |= a ^ b;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::super::encoding::hex_encode;
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        hex_encode(bytes, false)
    }

    #[test]
    fn sha256_matches_fips_180_vectors() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha1_matches_fips_180_vectors() {
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        // 1,000,000 repetitions of 'a' crosses many blocks.
        let long = vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&sha1(&long)),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231_cases() {
        // Test case 1.
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        // Test case 2.
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // Test case 6: a key longer than the block size.
        assert_eq!(
            hex(&hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn hmac_sha1_matches_rfc_2202_cases() {
        assert_eq!(
            hex(&hmac_sha1(&[0x0b; 20], b"Hi There")),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
        assert_eq!(
            hex(&hmac_sha1(b"Jefe", b"what do ya want for nothing?")),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
    }

    #[test]
    fn constant_time_eq_compares_content_and_length() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(constant_time_eq(b"", b""));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"abcd", b"abc"));
        // A prefix that is padded with zero bytes must not match its shorter form.
        assert!(!constant_time_eq(b"abc", b"abc\0"));
    }
}

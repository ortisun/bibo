//! Tar and gzip writers for the fakes.
//!
//! The fake package registry has to serve tarballs that `cargo` and `npm` accept, with a correct
//! checksum. The ingestion tests need archives with entries a careful extractor must refuse: a
//! path that climbs out of the target, an absolute path, a symbolic link, a hard link, a device
//! node. The testkit may not depend on an archive crate, so this file writes the two formats
//! itself. It only writes. Nothing here reads or extracts an archive.
//!
//! * [`tar`] writes the POSIX ustar format, with GNU long-name records for paths over 100 bytes.
//! * [`gzip`] wraps data in a gzip stream made of stored (uncompressed) deflate blocks, with the
//!   modification time zero, so the same input always gives the same bytes. The output is larger
//!   than the input. That is fine for a fixture, and the checksums stay stable.
//!
//! Both are checked in the tests with the system's `tar` and `gzip`.

/// What kind of entry to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// A regular file with this content.
    File(Vec<u8>),
    /// A directory.
    Directory,
    /// A symbolic link to this target, which may be absolute or climb out of the extraction root.
    Symlink(String),
    /// A hard link to this path.
    Hardlink(String),
    /// A character device node.
    CharDevice,
    /// A block device node.
    BlockDevice,
    /// A named pipe.
    Fifo,
}

/// One entry of an archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The path as written in the archive. It is not checked or cleaned, so a hostile path is
    /// possible on purpose.
    pub path: String,
    /// What the entry is.
    pub kind: Kind,
    /// The permission bits, such as `0o644`. A setuid bit (`0o4755`) is written as given.
    pub mode: u32,
}

impl Entry {
    /// A regular file, mode 0644.
    #[must_use]
    pub fn file(path: &str, content: &[u8]) -> Self {
        Self {
            path: path.to_owned(),
            kind: Kind::File(content.to_vec()),
            mode: 0o644,
        }
    }

    /// A directory, mode 0755.
    #[must_use]
    pub fn directory(path: &str) -> Self {
        Self {
            path: path.to_owned(),
            kind: Kind::Directory,
            mode: 0o755,
        }
    }

    /// A symbolic link.
    #[must_use]
    pub fn symlink(path: &str, target: &str) -> Self {
        Self {
            path: path.to_owned(),
            kind: Kind::Symlink(target.to_owned()),
            mode: 0o777,
        }
    }

    /// A hard link.
    #[must_use]
    pub fn hardlink(path: &str, target: &str) -> Self {
        Self {
            path: path.to_owned(),
            kind: Kind::Hardlink(target.to_owned()),
            mode: 0o644,
        }
    }

    /// The entry with other permission bits.
    #[must_use]
    pub fn with_mode(mut self, mode: u32) -> Self {
        self.mode = mode;
        self
    }
}

const BLOCK: usize = 512;

fn octal(value: u64, width: usize) -> Vec<u8> {
    // `width - 1` digits and a NUL, the usual ustar number field.
    let text = format!("{value:0>digits$o}", digits = width - 1);
    let mut bytes = text.into_bytes();
    bytes.push(0);
    bytes
}

fn put(header: &mut [u8; BLOCK], offset: usize, bytes: &[u8]) {
    let end = (offset + bytes.len()).min(BLOCK);
    header[offset..end].copy_from_slice(&bytes[..end - offset]);
}

fn header(path: &str, type_flag: u8, size: u64, mode: u32, link: &str) -> [u8; BLOCK] {
    let mut block = [0u8; BLOCK];
    let name = path.as_bytes();
    put(&mut block, 0, &name[..name.len().min(100)]);
    put(&mut block, 100, &octal(u64::from(mode), 8));
    put(&mut block, 108, &octal(0, 8)); // uid
    put(&mut block, 116, &octal(0, 8)); // gid
    put(&mut block, 124, &octal(size, 12));
    put(&mut block, 136, &octal(0, 12)); // mtime zero, so output is reproducible
    block[148..156].fill(b' '); // checksum field counts as spaces while summing
    block[156] = type_flag;
    let link = link.as_bytes();
    put(&mut block, 157, &link[..link.len().min(100)]);
    put(&mut block, 257, b"ustar\0");
    put(&mut block, 263, b"00");
    let sum: u32 = block.iter().map(|b| u32::from(*b)).sum();
    let mut field = format!("{sum:0>6o}").into_bytes();
    field.push(0);
    field.push(b' ');
    put(&mut block, 148, &field);
    block
}

fn push_data(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(data);
    let padding = (BLOCK - data.len() % BLOCK) % BLOCK;
    out.extend(std::iter::repeat_n(0u8, padding));
}

/// Writes a ustar archive of the entries, in order, ending with the two zero blocks.
#[must_use]
pub fn tar(entries: &[Entry]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        // A name or link target over 100 bytes goes in a GNU long-name record first.
        if entry.path.len() > 100 {
            let mut data = entry.path.clone().into_bytes();
            data.push(0);
            out.extend_from_slice(&header("././@LongLink", b'L', data.len() as u64, 0o644, ""));
            push_data(&mut out, &data);
        }
        let (flag, size, link, content): (u8, u64, &str, &[u8]) = match &entry.kind {
            Kind::File(bytes) => (b'0', bytes.len() as u64, "", bytes),
            Kind::Directory => (b'5', 0, "", &[]),
            Kind::Symlink(target) => (b'2', 0, target, &[]),
            Kind::Hardlink(target) => (b'1', 0, target, &[]),
            Kind::CharDevice => (b'3', 0, "", &[]),
            Kind::BlockDevice => (b'4', 0, "", &[]),
            Kind::Fifo => (b'6', 0, "", &[]),
        };
        out.extend_from_slice(&header(&entry.path, flag, size, entry.mode, link));
        push_data(&mut out, content);
    }
    out.extend(std::iter::repeat_n(0u8, 2 * BLOCK));
    out
}

/// The CRC-32 of `data` (the polynomial gzip uses).
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (!(crc & 1)).wrapping_add(1);
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Wraps `data` in a gzip stream of stored deflate blocks. Reproducible: no timestamp, no name.
#[must_use]
pub fn gzip(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
    if data.is_empty() {
        // One empty final stored block.
        out.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
    }
    let mut chunks = data.chunks(65_535).peekable();
    while let Some(chunk) = chunks.next() {
        let last = chunks.peek().is_none();
        out.push(u8::from(last));
        let length = chunk.len() as u16;
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(&(!length).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out.extend_from_slice(&crc32(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

/// A gzip-compressed tar archive, the shape of a `.crate` file and of an npm tarball.
#[must_use]
pub fn tar_gz(entries: &[Entry]) -> Vec<u8> {
    gzip(&tar(entries))
}

#[cfg(test)]
mod tests;

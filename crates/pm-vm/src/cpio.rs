//! A writer for the `newc` cpio format, the one format the kernel unpacks an
//! initramfs from.
//!
//! Hand-written rather than pulled in as a dependency because the format is a fixed
//! 110-byte ASCII header per member and nothing else: every field is eight hex
//! digits, the name follows NUL-terminated, and both the name and the data are
//! padded to four bytes. The kernel's reader (`init/initramfs.c`) is the
//! specification that matters, and it needs nothing this module does not emit.
//!
//! Members are written in the order they are added. The kernel creates each one
//! with a plain `open`/`mkdir`/`mknod`, so a directory has to be written before
//! anything inside it; [`super::Tree`] guarantees that by emitting in sorted order.

use std::{
    fs::File,
    io::{self, Read, Write},
    os::unix::ffi::OsStrExt,
    path::Path,
};

use miette::{IntoDiagnostic, WrapErr, miette};

/// `S_IFDIR`.
pub const DIRECTORY: u32 = 0o040_000;
/// `S_IFREG`.
pub const REGULAR: u32 = 0o100_000;
/// `S_IFLNK`.
pub const SYMLINK: u32 = 0o120_000;
/// `S_IFCHR`.
pub const CHARACTER_DEVICE: u32 = 0o020_000;

/// The magic every `newc` header starts with (no checksum variant).
const MAGIC: &[u8; 6] = b"070701";
/// The name of the member that ends the archive.
const TRAILER: &str = "TRAILER!!!";

/// A `newc` archive being written to `W`.
pub struct Newc<W: Write> {
    out: W,
    /// Bytes written so far, which is what the four-byte padding is relative to.
    offset: u64,
    /// Next inode number. Each member gets its own, so the kernel never mistakes two
    /// files for hard links of one another.
    inode: u32,
}

/// Everything in a member header besides the name.
#[derive(Clone, Copy)]
struct Header {
    mode: u32,
    size: u32,
    rdev_major: u32,
    rdev_minor: u32,
}

impl<W: Write> Newc<W> {
    /// Start an archive on `out`.
    pub fn new(out: W) -> Self {
        Self {
            out,
            offset: 0,
            inode: 1,
        }
    }

    /// Add a directory.
    ///
    /// # Errors
    ///
    /// Fails if `out` cannot be written to.
    pub fn directory(&mut self, name: &Path, permissions: u32) -> miette::Result<()> {
        self.header(name, Header::plain(DIRECTORY | permissions, 0))
    }

    /// Add a regular file holding `data`.
    ///
    /// # Errors
    ///
    /// Fails if `data` does not fit the format's 32-bit size field or `out` cannot be
    /// written to.
    pub fn bytes(&mut self, name: &Path, permissions: u32, data: &[u8]) -> miette::Result<()> {
        self.header(
            name,
            Header::plain(REGULAR | permissions, size(name, data.len())?),
        )?;
        self.write(data)?;
        self.pad()
    }

    /// Add a symbolic link pointing at `target`, which is stored verbatim.
    ///
    /// # Errors
    ///
    /// Fails if `out` cannot be written to.
    pub fn symlink(&mut self, name: &Path, target: &Path) -> miette::Result<()> {
        let target = target.as_os_str().as_bytes();
        self.header(
            name,
            Header::plain(SYMLINK | 0o777, size(name, target.len())?),
        )?;
        self.write(target)?;
        self.pad()
    }

    /// Add a character device node.
    ///
    /// The archive records the node, so building one needs no privilege: it is the
    /// kernel that calls `mknod` when it unpacks it.
    ///
    /// # Errors
    ///
    /// Fails if `out` cannot be written to.
    pub fn character_device(
        &mut self,
        name: &Path,
        permissions: u32,
        major: u32,
        minor: u32,
    ) -> miette::Result<()> {
        self.header(
            name,
            Header {
                mode: CHARACTER_DEVICE | permissions,
                size: 0,
                rdev_major: major,
                rdev_minor: minor,
            },
        )
    }

    /// Add a regular file copied from `source` on the host.
    ///
    /// The file is streamed rather than read into memory, because a package can carry
    /// files far larger than anything worth holding twice. Its length is taken once,
    /// before the header is written, and exactly that many bytes are copied: a file
    /// that changes size underneath the copy fails the archive rather than corrupting
    /// every member after it.
    ///
    /// # Errors
    ///
    /// Fails if `source` cannot be opened or read, if it is 4 GiB or larger, if it
    /// shrinks while being copied, or if `out` cannot be written to.
    pub fn file(&mut self, name: &Path, permissions: u32, source: &Path) -> miette::Result<()> {
        let file = File::open(source)
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot open {}", source.display()))?;
        let length = file
            .metadata()
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot stat {}", source.display()))?
            .len();
        let length = usize::try_from(length).unwrap_or(usize::MAX);
        self.header(
            name,
            Header::plain(REGULAR | permissions, size(name, length)?),
        )?;
        let expected = length as u64;
        let copied = io::copy(&mut file.take(expected), &mut self.out)
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot copy {} into the initramfs", source.display()))?;
        if copied != expected {
            return Err(miette!(
                "{} shrank from {expected} to {copied} bytes while it was copied into the \
                 initramfs",
                source.display()
            ));
        }
        self.offset += copied;
        self.pad()
    }

    /// Write the trailer and hand back the underlying writer.
    ///
    /// # Errors
    ///
    /// Fails if `out` cannot be written to or flushed.
    pub fn finish(mut self) -> miette::Result<W> {
        self.header(Path::new(TRAILER), Header::plain(0, 0))?;
        self.out.flush().into_diagnostic()?;
        Ok(self.out)
    }

    fn header(&mut self, name: &Path, header: Header) -> miette::Result<()> {
        let name = name.as_os_str().as_bytes();
        if name.is_empty() || name.contains(&0) {
            return Err(miette!(
                "{:?} cannot name an initramfs member",
                String::from_utf8_lossy(name)
            ));
        }
        // Directories and the trailer have one link; nothing here is ever hard-linked.
        let links = if header.mode & DIRECTORY == DIRECTORY {
            2
        } else {
            1
        };
        let fields = [
            self.inode,
            header.mode,
            0, // uid
            0, // gid
            links,
            0, // mtime: fixed, so the same inputs make the same archive
            header.size,
            0, // devmajor
            0, // devminor
            header.rdev_major,
            header.rdev_minor,
            size(Path::new(""), name.len() + 1)?,
            0, // check
        ];
        self.inode += 1;
        let mut rendered = Vec::with_capacity(110 + name.len() + 4);
        rendered.extend_from_slice(MAGIC);
        for field in fields {
            rendered.extend_from_slice(format!("{field:08x}").as_bytes());
        }
        rendered.extend_from_slice(name);
        rendered.push(0);
        self.write(&rendered)?;
        self.pad()
    }

    fn write(&mut self, bytes: &[u8]) -> miette::Result<()> {
        self.out
            .write_all(bytes)
            .into_diagnostic()
            .wrap_err("cannot write the initramfs")?;
        self.offset += bytes.len() as u64;
        Ok(())
    }

    /// Pad to the next four-byte boundary.
    fn pad(&mut self) -> miette::Result<()> {
        let padding = ((4 - (self.offset % 4)) % 4) as usize;
        self.write(&[0; 3][..padding])
    }
}

impl Header {
    fn plain(mode: u32, size: u32) -> Self {
        Self {
            mode,
            size,
            rdev_major: 0,
            rdev_minor: 0,
        }
    }
}

/// A length as the format's 32-bit size field.
fn size(name: &Path, length: usize) -> miette::Result<u32> {
    u32::try_from(length).map_err(|_| {
        miette!(
            "{} is {length} bytes, more than an initramfs member can hold",
            name.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_member_is_a_header_a_padded_name_and_padded_data() {
        let mut archive = Newc::new(Vec::new());
        archive.bytes(Path::new("a"), 0o644, b"hello").unwrap();
        let bytes = archive.finish().unwrap();

        assert_eq!(&bytes[..6], MAGIC);
        // 110-byte header, then "a\0" padded to 112, then 5 bytes padded to 120.
        assert_eq!(&bytes[110..112], b"a\0");
        assert_eq!(&bytes[112..117], b"hello");
        assert_eq!(&bytes[117..120], &[0, 0, 0]);
        assert_eq!(&bytes[120..126], MAGIC);
        // filesize is the seventh field.
        assert_eq!(&bytes[6 + 6 * 8..6 + 7 * 8], b"00000005");
        assert_eq!(bytes.len() % 4, 0);
    }

    #[test]
    fn a_device_node_records_its_numbers_and_no_data() {
        let mut archive = Newc::new(Vec::new());
        archive
            .character_device(Path::new("dev/console"), 0o600, 5, 1)
            .unwrap();
        let bytes = archive.finish().unwrap();
        let field = |index: usize| &bytes[6 + index * 8..6 + (index + 1) * 8];
        assert_eq!(field(1), b"00002180");
        assert_eq!(field(9), b"00000005");
        assert_eq!(field(10), b"00000001");
    }

    #[test]
    fn a_name_with_a_nul_is_refused() {
        let mut archive = Newc::new(Vec::new());
        let name = Path::new(std::ffi::OsStr::from_bytes(b"a\0b"));
        assert!(archive.directory(name, 0o755).is_err());
    }
}

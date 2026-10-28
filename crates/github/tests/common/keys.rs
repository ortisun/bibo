//! A throwaway RSA key, made when a test runs and never written anywhere that outlives it.
//!
//! No RSA key generator is on the dependency list (the `rsa` crate has an open advisory), so the
//! tests ask the `openssl` command line, which is also the independent implementation that checks
//! the signatures `ring` makes. When `openssl` is missing the test stops with a message that
//! starts `BLOCKED:`; it does not pass.

use std::path::Path;
use std::process::Command;

use factory_testkit::fx::tmpdir::FxTempDir;

/// Which PEM form to write: GitHub hands out PKCS#1, `openssl` writes PKCS#8 by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// `BEGIN RSA PRIVATE KEY`.
    Pkcs1,
    /// `BEGIN PRIVATE KEY`.
    Pkcs8,
}

/// A key pair on disk in a temporary directory, removed on drop.
pub struct Throwaway {
    dir: FxTempDir,
    /// The private key as PEM text.
    pub private_pem: String,
}

fn openssl(args: &[&str], cwd: &Path) -> Vec<u8> {
    let output = Command::new("openssl")
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "BLOCKED: the openssl command line is needed to make a throwaway key and to check \
                 signatures independently, and it could not start: {error}"
            )
        });
    assert!(
        output.status.success(),
        "openssl {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

impl Throwaway {
    /// Makes a 2048-bit key in the given form.
    ///
    /// # Panics
    /// With `BLOCKED:` when `openssl` is not available.
    pub fn new(form: Form) -> Self {
        let dir = FxTempDir::new("github-key").expect("a temporary directory");
        let args: &[&str] = match form {
            Form::Pkcs1 => &["genrsa", "-traditional", "-out", "key.pem", "2048"],
            Form::Pkcs8 => &["genrsa", "-out", "key.pem", "2048"],
        };
        openssl(args, dir.path());
        openssl(
            &["rsa", "-in", "key.pem", "-pubout", "-out", "pub.pem"],
            dir.path(),
        );
        let private_pem = std::fs::read_to_string(dir.join("key.pem")).expect("the key file");
        let label = match form {
            Form::Pkcs1 => "BEGIN RSA PRIVATE KEY",
            Form::Pkcs8 => "BEGIN PRIVATE KEY",
        };
        assert!(private_pem.contains(label), "unexpected key format");
        Self { dir, private_pem }
    }

    /// True when `openssl` verifies `signature` over `message` with the public key. This is the
    /// independent check: it shares no code with the signer.
    pub fn openssl_verifies(&self, message: &[u8], signature: &[u8]) -> bool {
        std::fs::write(self.dir.join("message.bin"), message).expect("write message");
        std::fs::write(self.dir.join("signature.bin"), signature).expect("write signature");
        Command::new("openssl")
            .args([
                "dgst",
                "-sha256",
                "-verify",
                "pub.pem",
                "-signature",
                "signature.bin",
                "message.bin",
            ])
            .current_dir(self.dir.path())
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

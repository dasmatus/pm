//! Ed25519 signing and verification for build files and packages.
//!
//! Signing is **required**, not optional: a build file and a package are both expected
//! to arrive with a signature, and an unsigned or badly signed artefact is an error
//! rather than a warning.
//!
//! Signatures are **detached**. Signing `foo.cpkg` writes `foo.cpkg.sig` beside it, so
//! a package travels as *two* files. That is deliberate: embedding the signature in the
//! archive would mean rewriting the very bytes the signature covers, and would force a
//! tar round-trip on every verification. The same shape is used for build files, so
//! there is exactly one rule to remember.
//!
//! # What is signed
//!
//! The payload is the **exact, complete byte string of the file**, as read from disk.
//! There is no canonicalisation, no re-serialisation and no framing header: [`sign_file`]
//! signs what it read, and [`verify_file`] verifies against a fresh read of the same
//! bytes. A single flipped byte anywhere in the file - archive member, YAML comment,
//! trailing newline - invalidates the signature.
//!
//! # Trust
//!
//! A signature verifies only when both halves hold: the Ed25519 check passes *and* the
//! signer's public key is present in the [`TrustStore`], a directory of `*.pub` files
//! each holding one public key as hex. A cryptographically perfect signature from an
//! unknown key is rejected, because otherwise anyone could sign anything.

use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs::{
        OpenOptions, Permissions, create_dir_all, metadata, read, read_dir, read_to_string,
        set_permissions, write,
    },
    io::Write as _,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

use miette::{IntoDiagnostic, WrapErr, miette};
use ring::{
    rand::SystemRandom,
    signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey},
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// The only algorithm this version produces or accepts. Recorded in every signature
/// file so a later version can add a second one without guessing at the old format.
const ALGORITHM: &str = "ed25519";

/// Length of a raw Ed25519 public key, in bytes.
const PUBLIC_KEY_LEN: usize = 32;

/// Length of a raw Ed25519 signature, in bytes.
const SIGNATURE_LEN: usize = 64;

/// Permission bits that must be clear on the private key file: any group or other
/// access at all means another account on the box can impersonate the signer.
const GROUP_AND_OTHER: u32 = 0o077;

/// An Ed25519 keypair on disk (PKCS#8 v2).
///
/// The private half never leaves this type: it is not `Clone`, not `Serialize`, and its
/// [`Debug`] shows only the public key. Only [`SigningKey::public_key_hex`] and
/// [`SigningKey::sign`] observe it, and neither reveals the seed.
pub struct SigningKey {
    pair: Ed25519KeyPair,
    path: PathBuf,
}

impl std::fmt::Debug for SigningKey {
    /// Deliberately prints the public key and the path only. Never add the private
    /// scalar, the seed or the PKCS#8 bytes here: `Debug` output ends up in logs.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SigningKey")
            .field("path", &self.path)
            .field("public_key", &self.public_key_hex())
            .finish()
    }
}

impl SigningKey {
    /// Load the key at `path`, or generate and persist one if absent (0600).
    ///
    /// A freshly generated key is logged at `warn` with its public key, because nothing
    /// trusts it yet: the caller (`pm sign`) is expected to feed that hex to
    /// [`TrustStore::add`], otherwise the user cannot verify their own work.
    ///
    /// # Errors
    ///
    /// Fails if the existing key file is group- or world-accessible, is not a regular
    /// file, is not a PKCS#8 v2 Ed25519 key, or cannot be read; and if a new key cannot
    /// be generated or written.
    pub fn load_or_create(path: &Path) -> miette::Result<Self> {
        if path.exists() {
            Self::load(path)
        } else {
            Self::create(path)
        }
    }

    /// Read and validate an existing key file.
    fn load(path: &Path) -> miette::Result<Self> {
        let stat = metadata(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("Could not stat the signing key at {}", path.display()))?;

        if !stat.is_file() {
            return Err(miette!(
                help = "The signing key must be a regular file holding a PKCS#8 v2 Ed25519 key.",
                "The signing key path {} is not a regular file.",
                path.display()
            ));
        }

        let mode = stat.permissions().mode() & 0o7777;
        if mode & GROUP_AND_OTHER != 0 {
            return Err(miette!(
                help = format!("Run `chmod 600 {}`.", path.display()),
                "The signing key {} is accessible to group or others (mode {mode:04o}); \
                 anyone with that access can sign packages as you.",
                path.display()
            ));
        }

        let pkcs8 = read(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("Could not read the signing key at {}", path.display()))?;

        // `from_pkcs8` (as opposed to `from_pkcs8_maybe_unchecked`) insists on v2, which
        // carries the public key, and checks the two halves against each other. That
        // turns a corrupted file into an error here instead of unverifiable signatures
        // later.
        let pair = Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|source| {
            miette!(
                help = format!(
                    "Expected an unencrypted PKCS#8 v2 Ed25519 key. Note that \
                     `openssl genpkey -algorithm ED25519` writes v1, which is not accepted. \
                     Move {} aside and let `pm sign` generate a fresh key.",
                    path.display()
                ),
                "The signing key {} is not a usable Ed25519 key: {source}",
                path.display()
            )
        })?;

        let key = Self {
            pair,
            path: path.to_path_buf(),
        };
        debug!(path = %path.display(), public_key = %key.public_key_hex(), "loaded signing key");
        Ok(key)
    }

    /// Generate a keypair and persist it at `path` with mode 0600.
    fn create(path: &Path) -> miette::Result<Self> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            create_dir_all(parent).into_diagnostic().wrap_err_with(|| {
                format!("Could not create the key directory {}", parent.display())
            })?;
            // Only tightened when this call created the directory, so an existing
            // shared config directory is never silently narrowed.
            set_permissions(parent, Permissions::from_mode(0o700))
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!("Could not restrict {} to the owner", parent.display())
                })?;
        }

        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).map_err(|_| {
            miette!(
                "Could not generate an Ed25519 keypair: the system random number generator refused."
            )
        })?;

        // `create_new` plus `mode` means the file is 0600 from the instant it exists:
        // there is no window in which the umask leaves the private key readable, and an
        // attacker cannot pre-create the path and have us write into it.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("Could not create the signing key at {}", path.display()))?;
        file.write_all(document.as_ref())
            .into_diagnostic()
            .wrap_err_with(|| format!("Could not write the signing key to {}", path.display()))?;
        file.sync_all()
            .into_diagnostic()
            .wrap_err_with(|| format!("Could not flush the signing key to {}", path.display()))?;

        let pair = Ed25519KeyPair::from_pkcs8(document.as_ref()).map_err(|source| {
            miette!("Just-generated Ed25519 keypair did not parse back: {source}")
        })?;

        let key = Self {
            pair,
            path: path.to_path_buf(),
        };
        warn!(
            path = %path.display(),
            public_key = %key.public_key_hex(),
            "generated a new signing key; nothing trusts it yet - add it to the trust store"
        );
        Ok(key)
    }

    /// The signer's public key, lowercase hex. Safe to log, print and publish.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        to_hex(self.pair.public_key().as_ref())
    }

    /// Detached signature over `payload`.
    #[must_use]
    pub fn sign(&self, payload: &[u8]) -> Vec<u8> {
        self.pair.sign(payload).as_ref().to_vec()
    }
}

/// A detached signature file: signature + signer public key + what was signed.
///
/// "What was signed" is the whole file's bytes - see the module documentation. The
/// algorithm is recorded explicitly so the format can grow a second one later without
/// having to guess what an old file meant.
///
/// Serialises to YAML as:
///
/// ```yaml
/// algorithm: ed25519
/// public_key: <64 hex chars>
/// signature: <128 hex chars>
/// ```
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    algorithm: String,
    public_key: String,
    signature: String,
}

impl Signature {
    /// Sign `payload` with `key`.
    #[must_use]
    pub fn create(key: &SigningKey, payload: &[u8]) -> Self {
        Self {
            algorithm: ALGORITHM.to_owned(),
            public_key: key.public_key_hex(),
            signature: to_hex(&key.sign(payload)),
        }
    }

    /// Render the signature as the YAML that goes in a `.sig` file.
    ///
    /// # Errors
    ///
    /// Fails only if serialisation itself fails.
    pub fn to_yaml(&self) -> miette::Result<String> {
        serde_yaml::to_string(self)
            .into_diagnostic()
            .wrap_err("Could not serialise the signature")
    }

    /// Parse a `.sig` file's contents.
    ///
    /// Structure is validated here - the algorithm must be known, and both hex fields
    /// must decode to the right length - so that a malformed file is reported as
    /// malformed rather than surfacing later as "does not verify".
    ///
    /// # Errors
    ///
    /// Fails if the YAML does not parse, names an unknown algorithm, or carries a
    /// public key or signature that is not hex of the expected length.
    pub fn from_yaml(text: &str) -> miette::Result<Self> {
        let signature: Self = serde_yaml::from_str(text)
            .into_diagnostic()
            .wrap_err("Could not parse the signature file as YAML")?;
        signature.decode()?;
        Ok(signature)
    }

    /// The signer's public key, lowercase hex.
    #[must_use]
    pub fn public_key_hex(&self) -> &str {
        &self.public_key
    }

    /// Verify against `payload`.
    ///
    /// Fails closed, and each way of failing has its own message: a malformed field, an
    /// untrusted signer, and a signature that simply does not match are three distinct
    /// diagnostics. Trust is checked before the maths so that a good signature from an
    /// unknown key says so, instead of blaming the bytes.
    ///
    /// # Errors
    ///
    /// Fails if the signature does not verify, or if the signer's key is not trusted.
    pub fn verify(&self, payload: &[u8], trust: &TrustStore) -> miette::Result<()> {
        let (public_key, signature) = self.decode()?;

        if !trust.trusts(&self.public_key) {
            return Err(miette!(
                help = trust.how_to_trust(&self.public_key),
                "The signature was made by the key {}, which this installation does not trust.",
                self.public_key
            ));
        }

        // `ring` does the comparison in constant time and rejects malleable encodings.
        UnparsedPublicKey::new(&ED25519, public_key.as_slice())
            .verify(payload, &signature)
            .map_err(|_| {
                miette!(
                    help = "The file was modified after it was signed, or the signature \
                            belongs to a different file. Re-fetch both and try again.",
                    "The Ed25519 signature from key {} does not match the signed bytes.",
                    self.public_key
                )
            })?;

        debug!(public_key = %self.public_key, bytes = payload.len(), "signature verified");
        Ok(())
    }

    /// Decode and length-check both hex fields, and reject an unknown algorithm.
    fn decode(&self) -> miette::Result<(Vec<u8>, Vec<u8>)> {
        if self.algorithm != ALGORITHM {
            return Err(miette!(
                help = format!("This version of pm only understands `{ALGORITHM}`."),
                "The signature names an unknown algorithm `{}`.",
                self.algorithm
            ));
        }

        let public_key = decode_key_hex(&self.public_key, PUBLIC_KEY_LEN, "public key")?;
        let signature = decode_key_hex(&self.signature, SIGNATURE_LEN, "signature")?;
        Ok((public_key, signature))
    }
}

/// Public keys this installation accepts.
///
/// An empty store trusts nobody, so every verification fails - which is the right
/// default, but means the "untrusted key" diagnostic has to explain how to populate it.
/// [`TrustStore::how_to_trust`] does that, naming the directory it was loaded from.
#[derive(Debug, Clone)]
pub struct TrustStore {
    dir: PathBuf,
    keys: BTreeSet<String>,
}

impl TrustStore {
    /// Load every `*.pub` under `dir`; an absent directory is an empty store.
    ///
    /// Each file holds one public key as hex, with surrounding whitespace ignored.
    /// Subdirectories are not descended into, and files with any other extension are
    /// skipped, so the directory can hold a README without breaking.
    ///
    /// # Errors
    ///
    /// Fails if the directory exists but cannot be read, or if any `*.pub` file in it is
    /// not a single valid Ed25519 public key in hex. A junk trust file is an error
    /// rather than a skip: silently ignoring it would quietly withdraw trust from a key
    /// the user believes is installed.
    pub fn load(dir: &Path) -> miette::Result<Self> {
        let mut keys = BTreeSet::new();

        if !dir.exists() {
            debug!(dir = %dir.display(), "no trust directory; trusting no keys");
            return Ok(Self {
                dir: dir.to_path_buf(),
                keys,
            });
        }

        let entries = read_dir(dir)
            .into_diagnostic()
            .wrap_err_with(|| format!("Could not read the trust directory {}", dir.display()))?;

        for entry in entries {
            let entry = entry.into_diagnostic().wrap_err_with(|| {
                format!(
                    "Could not read an entry of the trust directory {}",
                    dir.display()
                )
            })?;
            let path = entry.path();
            if path.extension().is_none_or(|extension| extension != "pub") || !path.is_file() {
                continue;
            }

            let text = read_to_string(&path)
                .into_diagnostic()
                .wrap_err_with(|| format!("Could not read the trusted key {}", path.display()))?;
            let hex = decode_key_hex(text.trim(), PUBLIC_KEY_LEN, "public key")
                .wrap_err_with(|| format!("The trusted key file {} is not usable", path.display()))
                .map(|bytes| to_hex(&bytes))?;

            keys.insert(hex);
        }

        debug!(dir = %dir.display(), keys = keys.len(), "loaded trust store");
        Ok(Self {
            dir: dir.to_path_buf(),
            keys,
        })
    }

    /// Whether `public_key_hex` names a trusted key. Hex case is not significant.
    #[must_use]
    pub fn trusts(&self, public_key_hex: &str) -> bool {
        self.keys
            .iter()
            .any(|trusted| trusted.eq_ignore_ascii_case(public_key_hex))
    }

    /// Trust `public_key_hex` from now on, persisting it as `<dir>/<key>.pub`.
    ///
    /// # Errors
    ///
    /// Fails if the hex is not a valid Ed25519 public key, or if the file cannot be
    /// written.
    pub fn add(&mut self, public_key_hex: &str, dir: &Path) -> miette::Result<()> {
        let canonical = to_hex(&decode_key_hex(
            public_key_hex.trim(),
            PUBLIC_KEY_LEN,
            "public key",
        )?);

        create_dir_all(dir)
            .into_diagnostic()
            .wrap_err_with(|| format!("Could not create the trust directory {}", dir.display()))?;

        let path = dir.join(format!("{canonical}.pub"));
        write(&path, format!("{canonical}\n"))
            .into_diagnostic()
            .wrap_err_with(|| format!("Could not write the trusted key {}", path.display()))?;

        self.keys.insert(canonical.clone());
        info!(public_key = %canonical, path = %path.display(), "trusted a signing key");
        Ok(())
    }

    /// The help text that tells a user how to trust the key that just got rejected.
    fn how_to_trust(&self, public_key_hex: &str) -> String {
        format!(
            "If you know this key belongs to the publisher, trust it by writing it to \
             {} - for example `mkdir -p {dir} && echo {key} > {dir}/{key}.pub`. \
             There are {count} trusted key(s) right now.",
            self.dir.display(),
            dir = self.dir.display(),
            key = public_key_hex,
            count = self.keys.len()
        )
    }
}

/// Default config locations, honouring `$XDG_CONFIG_HOME` then `$HOME`.
///
/// # Errors
///
/// Fails if neither variable gives an absolute directory.
pub fn default_key_path() -> miette::Result<PathBuf> {
    Ok(config_dir()?.join("pm").join("signing.key"))
}

/// Directory of trusted public keys, `<config>/pm/trusted/`.
///
/// # Errors
///
/// Fails if neither `$XDG_CONFIG_HOME` nor `$HOME` gives an absolute directory.
pub fn default_trust_dir() -> miette::Result<PathBuf> {
    Ok(config_dir()?.join("pm").join("trusted"))
}

/// `$XDG_CONFIG_HOME` when it is an absolute path, else `$HOME/.config`.
fn config_dir() -> miette::Result<PathBuf> {
    if let Some(configured) = std::env::var_os("XDG_CONFIG_HOME") {
        let path = PathBuf::from(configured);
        // The XDG spec says a relative (or empty) value must be ignored as if unset.
        if path.is_absolute() {
            return Ok(path);
        }
        warn!("XDG_CONFIG_HOME is not an absolute path; falling back to $HOME/.config");
    }

    let home = std::env::var_os("HOME").ok_or_else(|| {
        miette!(
            help = "Set $HOME, or point $XDG_CONFIG_HOME at an absolute directory.",
            "Neither $XDG_CONFIG_HOME nor $HOME names a directory to keep signing keys in."
        )
    })?;

    let home = PathBuf::from(home);
    if !home.is_absolute() {
        return Err(miette!(
            help = "Set $HOME to an absolute path, or point $XDG_CONFIG_HOME at one.",
            "$HOME is not an absolute path: {}",
            home.display()
        ));
    }

    Ok(home.join(".config"))
}

/// Sign any file, writing `<file>.sig` next to it. Returns the signature path.
///
/// The payload is the file's exact bytes. The suffix is *appended* to the whole name,
/// so `pkg.cpkg` gains `pkg.cpkg.sig` and the original extension stays legible.
///
/// # Errors
///
/// Fails if the file cannot be read or the signature cannot be written.
pub fn sign_file(path: &Path, key: &SigningKey) -> miette::Result<PathBuf> {
    let payload = read(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("Could not read {} to sign it", path.display()))?;

    let signature = Signature::create(key, &payload);
    let destination = signature_path(path);
    write(&destination, signature.to_yaml()?)
        .into_diagnostic()
        .wrap_err_with(|| format!("Could not write the signature to {}", destination.display()))?;

    info!(
        file = %path.display(),
        signature = %destination.display(),
        public_key = %key.public_key_hex(),
        bytes = payload.len(),
        "signed"
    );
    Ok(destination)
}

/// Verify `<file>.sig` against `file`.
///
/// # Errors
///
/// Fails if the `.sig` is missing, malformed, does not verify, or is from an untrusted
/// key. Each of those is a separate message: an absent signature is a different problem
/// from an untrusted signer, which is a different problem from tampered bytes.
pub fn verify_file(path: &Path, trust: &TrustStore) -> miette::Result<()> {
    let signature_file = signature_path(path);

    if !signature_file.exists() {
        return Err(miette!(
            help = format!(
                "Sign it with `pm sign {}`, or fetch the `.sig` that the publisher shipped alongside it.",
                path.display()
            ),
            "{} has no signature: expected {} next to it.",
            path.display(),
            signature_file.display()
        ));
    }

    let text = read_to_string(&signature_file)
        .into_diagnostic()
        .wrap_err_with(|| format!("Could not read the signature {}", signature_file.display()))?;

    let signature = Signature::from_yaml(&text).wrap_err_with(|| {
        format!(
            "The signature file {} is malformed",
            signature_file.display()
        )
    })?;

    let payload = read(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("Could not read {} to verify it", path.display()))?;

    signature
        .verify(&payload, trust)
        .wrap_err_with(|| format!("{} failed verification", path.display()))?;

    debug!(file = %path.display(), public_key = %signature.public_key_hex(), "verified");
    Ok(())
}

/// `<path>.sig`, appending to the full file name rather than replacing the extension.
fn signature_path(path: &Path) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(".sig");
    PathBuf::from(name)
}

/// Lowercase hex, without pulling in a dependency for sixteen digits.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut text, byte| {
            text.push(char::from(DIGITS[usize::from(byte >> 4)]));
            text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
            text
        })
}

/// Decode `text` as hex and check it is exactly `expected` bytes long.
///
/// `what` names the field for the diagnostic ("public key", "signature").
fn decode_key_hex(text: &str, expected: usize, what: &str) -> miette::Result<Vec<u8>> {
    let bytes = from_hex(text).ok_or_else(|| {
        miette!(
            help = format!(
                "A {what} is written as {} lowercase hex characters.",
                expected * 2
            ),
            "The {what} `{text}` is not valid hex."
        )
    })?;

    if bytes.len() != expected {
        return Err(miette!(
            help = format!(
                "Expected {expected} bytes ({} hex characters).",
                expected * 2
            ),
            "The {what} is {} bytes long, not {expected}.",
            bytes.len()
        ));
    }

    Ok(bytes)
}

/// Decode a hex string of either case; `None` on any non-hex character or odd length.
fn from_hex(text: &str) -> Option<Vec<u8>> {
    let digits = text.as_bytes();
    if !digits.len().is_multiple_of(2) {
        return None;
    }

    digits
        .chunks_exact(2)
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16)?;
            let low = char::from(pair[1]).to_digit(16)?;
            u8::try_from(high * 16 + low).ok()
        })
        .collect()
}

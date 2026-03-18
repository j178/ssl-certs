use std::error::Error as StdError;
use std::path::{Path, PathBuf};
use std::{env, fmt, fs, io};

use pki_types::CertificateDer;
use pki_types::pem::{self, PemObject};

const ENV_CERT_FILE: &str = "SSL_CERT_FILE";
const ENV_CERT_DIR: &str = "SSL_CERT_DIR";

/// Load certificates from the paths specified in the environment variables
/// `SSL_CERT_FILE` and `SSL_CERT_DIR`.
///
/// If neither variable is set, returns an empty [`CertificateResult`].
pub fn load_certs_from_env() -> CertificateResult {
    let cert_file = env::var_os(ENV_CERT_FILE).map(PathBuf::from);
    // Read `SSL_CERT_DIR`, split it on the platform delimiter (`:` on Unix, `;` on Windows),
    // and return the entries as `PathBuf`s.
    //
    // See <https://docs.openssl.org/3.5/man1/openssl-rehash/#options>
    let cert_dirs = match env::var_os(ENV_CERT_DIR) {
        Some(dirs) => env::split_paths(&dirs).collect(),
        None => Vec::new(),
    };

    load_certs_from_paths_internal(cert_file.as_deref(), &cert_dirs)
}

/// Load certificates from the given paths.
///
/// If both are `None`, returns an empty [`CertificateResult`].
///
/// If `file` is `Some`, it is always used, so it must be a path to an existing,
/// accessible file from which certificates can be loaded successfully. While parsing,
/// the rustls-pki-types PEM parser will ignore parts of the file which are
/// not considered part of a certificate. Certificates which are not in the right
/// format (PEM) or are otherwise corrupted may get ignored silently.
///
/// If `dir` is defined, a directory must exist at this path, and all files
/// contained in it must be loaded successfully, subject to the rules outlined above for `file`.
/// The directory is not scanned recursively and may be empty.
pub fn load_certs_from_paths(file: Option<&Path>, dir: Option<&Path>) -> CertificateResult {
    let dirs = match dir {
        Some(d) => vec![d],
        None => Vec::new(),
    };

    load_certs_from_paths_internal(file, dirs.as_ref())
}

fn load_certs_from_paths_internal(
    file: Option<&Path>,
    dirs: &[impl AsRef<Path>],
) -> CertificateResult {
    let mut out = CertificateResult::default();
    if file.is_none() && dirs.is_empty() {
        return out;
    }

    if let Some(cert_file) = file {
        load_pem_certs(cert_file, &mut out);
    }

    for cert_dir in dirs {
        load_pem_certs_from_dir(cert_dir.as_ref(), &mut out);
    }

    out.certs.sort_unstable_by(|a, b| a.cmp(b));
    out.certs.dedup();
    out
}

/// Load certificate from certificate directory (what OpenSSL calls CAdir)
fn load_pem_certs_from_dir(dir: &Path, out: &mut CertificateResult) {
    let dir_reader = match fs::read_dir(dir) {
        Ok(reader) => reader,
        Err(err) => {
            out.io_error(err, dir, "opening directory");
            return;
        }
    };

    for entry in dir_reader {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                out.io_error(err, dir, "reading directory entries");
                continue;
            }
        };

        let path = entry.path();

        // `openssl rehash` used to create this directory uses symlinks. So,
        // make sure we resolve them.
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // Dangling symlink
                continue;
            }
            Err(e) => {
                out.io_error(e, &path, "failed to open file");
                continue;
            }
        };

        if metadata.is_file() {
            load_pem_certs(&path, out);
        }
    }
}

fn load_pem_certs(path: &Path, out: &mut CertificateResult) {
    let iter = match CertificateDer::pem_file_iter(path) {
        Ok(iter) => iter,
        Err(err) => {
            out.pem_error(err, path);
            return;
        }
    };

    for result in iter {
        match result {
            Ok(cert) => out.certs.push(cert),
            Err(err) => out.pem_error(err, path),
        }
    }
}

/// Results from trying to load certificates from the platform's native store.
#[non_exhaustive]
#[derive(Debug, Default)]
pub struct CertificateResult {
    /// Any certificates that were successfully loaded.
    pub certs: Vec<CertificateDer<'static>>,
    /// Any errors encountered while loading certificates.
    pub errors: Vec<Error>,
}

impl CertificateResult {
    /// Return the found certificates if no error occurred, otherwise panic.
    #[track_caller]
    pub fn expect(self, msg: &str) -> Vec<CertificateDer<'static>> {
        match self.errors.is_empty() {
            true => self.certs,
            false => panic!("{msg}: {:?}", self.errors),
        }
    }

    /// Return the found certificates if no error occurred, otherwise panic.
    #[track_caller]
    pub fn unwrap(self) -> Vec<CertificateDer<'static>> {
        match self.errors.is_empty() {
            true => self.certs,
            false => panic!(
                "errors occurred while loading certificates: {:?}",
                self.errors
            ),
        }
    }

    fn pem_error(&mut self, err: pem::Error, path: &Path) {
        self.errors.push(Error {
            context: "failed to read PEM from file",
            kind: match err {
                pem::Error::Io(err) => ErrorKind::Io {
                    inner: err,
                    path: path.to_owned(),
                },
                _ => ErrorKind::Pem(err),
            },
        });
    }

    fn io_error(&mut self, err: io::Error, path: &Path, context: &'static str) {
        self.errors.push(Error {
            context,
            kind: ErrorKind::Io {
                inner: err,
                path: path.to_owned(),
            },
        });
    }
}

#[non_exhaustive]
#[derive(Debug)]
pub enum ErrorKind {
    Io { inner: io::Error, path: PathBuf },
    Os(Box<dyn StdError + Send + Sync + 'static>),
    Pem(pem::Error),
}

#[derive(Debug)]
pub struct Error {
    pub context: &'static str,
    pub kind: ErrorKind,
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(match &self.kind {
            ErrorKind::Io { inner, .. } => inner,
            ErrorKind::Os(err) => &**err,
            ErrorKind::Pem(err) => err,
        })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.context)?;
        f.write_str(": ")?;
        match &self.kind {
            ErrorKind::Io { inner, path } => {
                write!(f, "{inner} at '{}'", path.display())
            }
            ErrorKind::Os(err) => err.fmt(f),
            ErrorKind::Pem(err) => err.fmt(f),
        }
    }
}

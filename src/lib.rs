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

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    #[cfg(unix)]
    use std::fs::Permissions;
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn deduplication() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let cert1 = include_str!("../tests/badssl-com-chain.pem");
        let cert2 = include_str!("../tests/one-existing-ca.pem");
        let file_path = temp_dir.path().join("ca-certificates.crt");
        let dir_path = temp_dir.path().to_path_buf();

        {
            let mut file = File::create(&file_path).unwrap();
            write!(file, "{}", &cert1).unwrap();
            write!(file, "{}", &cert2).unwrap();
        }

        {
            // Duplicate (already in `file_path`)
            let mut file = File::create(dir_path.join("71f3bb26.0")).unwrap();
            write!(file, "{}", &cert1).unwrap();
        }

        {
            // Duplicate (already in `file_path`)
            let mut file = File::create(dir_path.join("912e7cd5.0")).unwrap();
            write!(file, "{}", &cert2).unwrap();
        }

        let result = load_certs_from_paths(Some(&file_path), None);
        assert_eq!(result.certs.len(), 2);

        let result = load_certs_from_paths(None, Some(&dir_path));
        assert_eq!(result.certs.len(), 2);

        let result = load_certs_from_paths(Some(&file_path), Some(&dir_path));
        assert_eq!(result.certs.len(), 2);
    }

    #[test]
    fn malformed_file_from_env() {
        // Certificate parser tries to extract certs from file ignoring
        // invalid sections.
        let mut result = CertificateResult::default();
        load_pem_certs(Path::new(file!()), &mut result);
        assert_eq!(result.certs.len(), 0);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn from_env_missing_file() {
        let mut result = CertificateResult::default();
        load_pem_certs(Path::new("no/such/file"), &mut result);
        match &first_error(&result).kind {
            ErrorKind::Io { inner, .. } => assert_eq!(inner.kind(), io::ErrorKind::NotFound),
            _ => panic!("unexpected error {:?}", result.errors),
        }
    }

    #[test]
    fn from_env_missing_dir() {
        let mut result = CertificateResult::default();
        load_pem_certs_from_dir(Path::new("no/such/directory"), &mut result);
        match &first_error(&result).kind {
            ErrorKind::Io { inner, .. } => assert_eq!(inner.kind(), io::ErrorKind::NotFound),
            _ => panic!("unexpected error {:?}", result.errors),
        }
    }

    #[test]
    #[cfg(unix)]
    fn from_env_with_non_regular_and_empty_file() {
        let mut result = CertificateResult::default();
        load_pem_certs(Path::new("/dev/null"), &mut result);
        assert_eq!(result.certs.len(), 0);
        assert!(result.errors.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn from_env_bad_dir_perms() {
        // Create a temp dir that we can't read from.
        let temp_dir = tempfile::TempDir::new().unwrap();
        fs::set_permissions(temp_dir.path(), Permissions::from_mode(0o000)).unwrap();

        test_cert_paths_bad_perms(None, &[temp_dir.path()]);
    }

    #[test]
    #[cfg(unix)]
    fn from_env_bad_file_perms() {
        // Create a tmp dir with a file inside that we can't read from.
        let temp_dir = tempfile::TempDir::new().unwrap();
        let file_path = temp_dir.path().join("unreadable.pem");
        let cert_file = File::create(&file_path).unwrap();
        cert_file
            .set_permissions(Permissions::from_mode(0o000))
            .unwrap();

        test_cert_paths_bad_perms(Some(&file_path), &[]);
    }

    #[cfg(unix)]
    fn test_cert_paths_bad_perms(file: Option<&Path>, dirs: &[&Path]) {
        let result = load_certs_from_paths_internal(file, dirs);

        if let (None, true) = (file, dirs.is_empty()) {
            panic!("only one of file or dir should be set");
        };

        let error = first_error(&result);
        match &error.kind {
            ErrorKind::Io { inner, .. } => {
                assert_eq!(inner.kind(), io::ErrorKind::PermissionDenied);
                inner
            }
            _ => panic!("unexpected error {:?}", result.errors),
        };
    }

    fn first_error(result: &CertificateResult) -> &Error {
        result.errors.first().unwrap()
    }
}

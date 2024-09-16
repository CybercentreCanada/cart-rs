//!
//! The [Digester] trait wraps hashes and counter objects to produce hashes or summaries
//! to include in a cart file footer.
//! 

use sha2::Digest;

/// Interface for digests that produce footer entries
pub trait Digester {
    /// Consume data, updating the digest state
    fn update(&mut self, data: &[u8]);
    /// Key to store the finished value under
    fn name(&self) -> String;
    /// Complete processing and produce the final output. 
    /// As a string for backwards compatabilty reasons
    fn finish(&mut self) -> String;
}

/// Generate the default set of digests taken for cart files.
///
/// This includes the md5, sha1, sha256 hashes, and the length of the file.
#[must_use]
pub fn default_digesters() -> Vec<Box<dyn Digester>> {
    vec![
        #[cfg(feature = "md5")]
        Box::new(MD5Digest::new()),
        #[cfg(feature = "sha1")]
        Box::new(SHA1Digest::new()),
        Box::new(SHA256Digest::new()),
        Box::new(LengthDigest::new()),
    ]
}

#[cfg(feature = "md5")]
/// Calculates the MD5 of the file body
#[derive(Default)]
#[must_use]
pub struct MD5Digest {
    hasher: md5::Md5
}

#[cfg(feature = "md5")]
impl MD5Digest {
    /// Create digester to produce MD5
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(feature = "md5")]
impl Digester for MD5Digest {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn name(&self) -> String {
        "md5".to_owned()
    }

    fn finish(&mut self) -> String {
        format!("{:x}", self.hasher.finalize_reset())
    }
}

#[cfg(feature = "sha1")]
/// Calculates the SHA1 of the file body
#[derive(Default)]
#[must_use]
pub struct SHA1Digest {
    hasher: sha1::Sha1
}

#[cfg(feature = "sha1")]
impl SHA1Digest {
    /// Create new digester to produce SHA1
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(feature = "sha1")]
impl Digester for SHA1Digest {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn name(&self) -> String {
        "sha1".to_owned()
    }

    fn finish(&mut self) -> String {
        format!("{:x}", self.hasher.finalize_reset())
    }
}

/// Calculates the SHA256 of the file body
#[derive(Default)]
#[must_use]
pub struct SHA256Digest {
    hasher: sha2::Sha256
}

impl SHA256Digest {
    /// Create new digester to produce SHA256
    pub fn new() -> Self {
        Self::default()
    }
}

impl Digester for SHA256Digest {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn name(&self) -> String {
        return "sha256".to_owned()
    }

    fn finish(&mut self) -> String {
        format!("{:x}", self.hasher.finalize_reset())
    }
}

/// Accumulates the length of the file body
#[derive(Default)]
#[must_use]
pub struct LengthDigest {
    counter: u64
}

impl LengthDigest {
    /// Create new digester to produce file length
    pub fn new() -> Self {
        Self::default()
    }
}

impl Digester for LengthDigest {
    fn update(&mut self, data: &[u8]) {
        self.counter += data.len() as u64;
    }

    fn name(&self) -> String {
        return "length".to_owned()
    }

    fn finish(&mut self) -> String {
        format!("{}", self.counter)
    }
}
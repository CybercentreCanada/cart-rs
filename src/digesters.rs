///
/// The [Digester] trait wraps hashes and counter objects to produce hashes or summaries to include in a cart file footer.
///

use md5::Digest;

pub trait Digester {
    fn update(&mut self, data: &[u8]) -> anyhow::Result<()>;
    fn name(&self) -> String;
    fn finish(&mut self) -> String;
}

/// Generate the default set of digests taken for cart files.
///
/// This includes the md5, sha1, sha256 hashes, and the length of the file.
pub fn default_digesters() -> Vec<Box<dyn Digester>> {
    vec![
        Box::new(MD5Digest::new()),
        Box::new(SHA1Digest::new()),
        Box::new(SHA256Digest::new()),
        Box::new(LengthDigest::new()),
    ]
}

pub struct MD5Digest {
    hasher: md5::Md5
}

impl MD5Digest {
    pub fn new() -> Self {
        Self {
            hasher: md5::Md5::new()
        }
    }
}

impl Digester for MD5Digest {
    fn update(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.hasher.update(data);
        return Ok(())
    }

    fn name(&self) -> String {
        return "md5".to_owned()
    }

    fn finish(&mut self) -> String {
        format!("{:x}", self.hasher.finalize_reset())
    }
}

pub struct SHA1Digest {
    hasher: sha1::Sha1
}

impl SHA1Digest {
    pub fn new() -> Self {
        Self {
            hasher: sha1::Sha1::new()
        }
    }
}

impl Digester for SHA1Digest {
    fn update(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.hasher.update(data);
        return Ok(())
    }

    fn name(&self) -> String {
        return "sha1".to_owned()
    }

    fn finish(&mut self) -> String {
        format!("{:x}", self.hasher.finalize_reset())
    }
}

pub struct SHA256Digest {
    hasher: sha2::Sha256
}

impl SHA256Digest {
    pub fn new() -> Self {
        Self {
            hasher: sha2::Sha256::new()
        }
    }
}

impl Digester for SHA256Digest {
    fn update(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.hasher.update(data);
        return Ok(())
    }

    fn name(&self) -> String {
        return "sha256".to_owned()
    }

    fn finish(&mut self) -> String {
        format!("{:x}", self.hasher.finalize_reset())
    }
}

pub struct LengthDigest {
    counter: u64
}

impl LengthDigest {
    pub fn new() -> Self {
        Self {
            counter: 0
        }
    }
}

impl Digester for LengthDigest {
    fn update(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.counter += data.len() as u64;
        return Ok(())
    }

    fn name(&self) -> String {
        return "length".to_owned()
    }

    fn finish(&mut self) -> String {
        format!("{}", self.counter)
    }
}
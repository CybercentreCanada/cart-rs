///
/// The [Digester] trait wraps hashes and counter objects to produce hashes or summaries
/// to include in a cart file footer.
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
        Box::<MD5Digest>::default(),
        Box::<SHA1Digest>::default(),
        Box::<SHA256Digest>::default(),
        Box::<LengthDigest>::default(),
    ]
}

pub struct MD5Digest {
    hasher: md5::Md5,
}

impl Default for MD5Digest {
    fn default() -> Self {
        Self {
            hasher: md5::Md5::new(),
        }
    }
}

impl Digester for MD5Digest {
    fn update(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.hasher.update(data);
        Ok(())
    }

    fn name(&self) -> String {
        "md5".into()
    }

    fn finish(&mut self) -> String {
        format!("{:x}", self.hasher.finalize_reset())
    }
}

pub struct SHA1Digest {
    hasher: sha1::Sha1,
}

impl Default for SHA1Digest {
    fn default() -> Self {
        Self {
            hasher: sha1::Sha1::new(),
        }
    }
}

impl Digester for SHA1Digest {
    fn update(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.hasher.update(data);
        Ok(())
    }

    fn name(&self) -> String {
        "sha1".into()
    }

    fn finish(&mut self) -> String {
        format!("{:x}", self.hasher.finalize_reset())
    }
}

pub struct SHA256Digest {
    hasher: sha2::Sha256,
}

impl Default for SHA256Digest {
    fn default() -> Self {
        Self {
            hasher: sha2::Sha256::new(),
        }
    }
}

impl Digester for SHA256Digest {
    fn update(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.hasher.update(data);
        Ok(())
    }

    fn name(&self) -> String {
        "sha256".into()
    }

    fn finish(&mut self) -> String {
        format!("{:x}", self.hasher.finalize_reset())
    }
}

#[derive(Default)]
pub struct LengthDigest {
    counter: u64,
}

impl Digester for LengthDigest {
    fn update(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.counter += data.len() as u64;
        Ok(())
    }

    fn name(&self) -> String {
        "length".into()
    }

    fn finish(&mut self) -> String {
        format!("{}", self.counter)
    }
}

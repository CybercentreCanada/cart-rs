use std::io::{Write, Read};
use anyhow::Context;
use bytes::{BufMut, Buf};
use rc4::{KeyInit, StreamCipher};

use crate::digesters::Digester;

/// Alias for a serde mapping cart will accept for metadata.
pub type JsonMap = serde_json::Map<String, serde_json::Value>;

type Rc4 = rc4::Rc4::<rc4::consts::U16>;

// First 8 digits of PI twice.
const DEFAULT_RC4_KEY: [u8; 16] = [
    0x03, 0x01, 0x04, 0x01, 0x05, 0x09, 0x02, 0x06,
    0x03, 0x01, 0x04, 0x01, 0x05, 0x09, 0x02, 0x06
];

// Constants regarding header and footer encoding
const MAJOR_VERSION: i16 = 1;
const MANDATORY_HEADER_SIZE: usize = 38;
const MANDATORY_FOOTER_SIZE: usize = 8 * 3 + 4;
const BLOCK_SIZE: usize = 64 * 1024;
const HEADER_MAGIC: &[u8; 4] = b"CART";
const FOOTER_MAGIC: &[u8; 4] = b"TRAC";
const RESERVED: u64 = 0;

// A utility object that adapts a writer to apply the RC4 cypher as data is written.
struct CipherPassthroughOut<'a, OUT: Write> {
    cipher: Rc4,
    output: &'a mut OUT,
    buffer: Vec<u8>,
}

impl<'a, OUT: Write> Write for CipherPassthroughOut<'a, OUT> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.resize(buf.len(), 0);
        if let Err(err) = self.cipher.apply_keystream_b2b(buf, &mut self.buffer) {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, anyhow::anyhow!(err)))
        };
        self.output.write_all(&self.buffer[0..buf.len()])?;
        return Ok(buf.len());
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.output.flush()
    }
}


pub fn pack_stream<IN: Read, OUT: Write>(mut istream: IN, mut ostream: OUT,
    optional_header: Option<JsonMap>, optional_footer: Option<JsonMap>,
    mut digesters: Vec<Box<dyn Digester>>, rc4_key_override: Option<Vec<u8>>) -> anyhow::Result<()>
{
    let (rc4_key, key_override) = match rc4_key_override {
        Some(key) => (key, true),
        None => (DEFAULT_RC4_KEY.to_vec(), false),
    };

    // Build the optional header first if necessary. We need to know
    // it's size before serializing the mandatory header.
    let mut opt_header_len: u64 = 0;
    let mut opt_header_crypt = None;
    let mut pos: u64 = 0;

    if let Some(header) = optional_header {
        // JSON encode
        let mut opt_header_buffer = serde_json::to_vec(&header)?;

        // RC4
        let mut cipher = Rc4::new_from_slice(&rc4_key).context("Bad RC4 Key")?;
        cipher.try_apply_keystream(&mut opt_header_buffer)?;

        opt_header_len = opt_header_buffer.len() as u64;
        opt_header_crypt = Some(opt_header_buffer);
    };

    // Write the mandatory header
    ostream.write_all(&{
        // Build the header in a buffer first
        let mut header = vec![];
        header.reserve(MANDATORY_HEADER_SIZE);
        header.put_slice(HEADER_MAGIC); // MAGIC
        header.put_i16_le(MAJOR_VERSION); // MAJOR VERSION
        header.put_u64_le(RESERVED); // Reserved
        if key_override {
            header.put_bytes(0, 16);
        } else {
            header.put_slice(&rc4_key);
        }
        header.put_u64_le(opt_header_len); // optional header length

        // Check the header, and write it
        pos += header.len() as u64;
        if header.len() != MANDATORY_HEADER_SIZE {
            return Err(anyhow::anyhow!("Header encoding error"))
        }
        header
    })?;

    // Write optional header
    if let Some(buffer) = opt_header_crypt {
        pos += buffer.len() as u64;
        ostream.write_all(&buffer)?;
    };

    // Create new processors for rc4
    let cipher = Rc4::new_from_slice(&rc4_key)?;

    // Create a zlib processor which will write its output to the passthrough
    // processor which will rc4 it before writing to the output stream
    let mut bz = flate2::write::ZlibEncoder::new(
        CipherPassthroughOut{cipher, output: &mut ostream, buffer: vec![0u8; BLOCK_SIZE]},
        flate2::Compression::fast());
    let mut buffer = vec![0u8; BLOCK_SIZE];
    loop {
        // read the next block from input
        let bytes_read = istream.read(&mut buffer)?;
        if bytes_read == 0 {
            break
        }

        // update the various digests with this block
        for digest in digesters.iter_mut() {
            digest.update(&buffer[0..bytes_read])?;
        }

        // compress and then cipher any resulting output blocks
        bz.write_all(&buffer[0..bytes_read])?;
    }

    // Finish any remaining data in compressor
    pos += bz.total_out();
    bz.finish()?;

    // insert any requests digests into the optional footer.
    let mut optional_footer = optional_footer.unwrap_or_default();
    for mut digest in digesters {
        optional_footer.insert(digest.name(), serde_json::Value::String(digest.finish()));
    }

    let opt_footer_pos = pos;
    let mut opt_footer_buffer = serde_json::to_vec(&optional_footer)?;
    let mut cipher = Rc4::new_from_slice(&rc4_key)?;
    cipher.try_apply_keystream(&mut opt_footer_buffer)?;
    let opt_footer_len = opt_footer_buffer.len() as u64;
    ostream.write_all(&opt_footer_buffer)?;

    // Write the mandatory footer
    ostream.write_all(&{
        // Build the header in a buffer first
        let mut footer = vec![];
        footer.reserve(MANDATORY_FOOTER_SIZE);
        footer.put_slice(FOOTER_MAGIC); // MAGIC
        footer.put_u64_le(RESERVED); // Reserved
        footer.put_u64_le(opt_footer_pos);
        footer.put_u64_le(opt_footer_len);

        // Check the footer, and write it
        if footer.len() != MANDATORY_FOOTER_SIZE {
            return Err(anyhow::anyhow!("Footer encoding error"))
        }
        footer
    })?;
    ostream.flush()?;
    return Ok(())
}

pub (crate) fn _unpack_required_header<IN: Read>(mut istream: IN, rc4_key_override: Option<Vec<u8>>)
    -> anyhow::Result<(Vec<u8>, u64, u64)>
{
    //     # unpack to output stream, return header / footer
    //     # First read and unpack the mandatory header. This will tell us the RC4 key
    //     # and optional header length.
    //     # Optional header and rest of document are RC4'd
    let mut pos: u64 = 0;

//     # Read and unpack the madatory header.
    let mut header_buffer = vec![0u8; MANDATORY_HEADER_SIZE];
    istream.read_exact(&mut header_buffer)?;
    pos += MANDATORY_HEADER_SIZE as u64;
    let mut header_buffer = bytes::Bytes::from(header_buffer);

    {
        if !header_buffer.starts_with(HEADER_MAGIC) {
            return Err(anyhow::anyhow!("Could not unpack mandatory header"))
        }
        header_buffer.advance(HEADER_MAGIC.len());
        if header_buffer.get_i16_le() != MAJOR_VERSION {
            return Err(anyhow::anyhow!("Could not unpack mandatory header"))
        }
        if header_buffer.get_u64_le() != RESERVED {
            return Err(anyhow::anyhow!("Could not unpack mandatory header"))
        }
    }
    let rc4_key = header_buffer.copy_to_bytes(16);
    let opt_header_len = header_buffer.get_u64_le();

    let rc4_key = match rc4_key_override {
        Some(key) => key,
        None => rc4_key.to_vec(),
    };

    return Ok((rc4_key, opt_header_len, pos))
}


pub (crate) fn _unpack_header<IN: Read>(mut istream: IN, rc4_key_override: Option<Vec<u8>>)
    -> anyhow::Result<(Vec<u8>, Option<JsonMap>, u64)>
{
    let (rc4_key, opt_header_len, mut pos) = _unpack_required_header(&mut istream, rc4_key_override)?;
//     # Read and unpack any optional header.
    let mut optional_header = None;
    if opt_header_len > 0 {
        let mut buffer = vec![0u8; opt_header_len as usize];
        istream.read_exact(&mut buffer)?;
        pos += opt_header_len;

        let mut cipher = Rc4::new_from_slice(&rc4_key)?;
        cipher.try_apply_keystream(&mut buffer)?;
        optional_header = Some(serde_json::from_slice(&buffer)?);
    }
    return Ok((rc4_key, optional_header, pos))
}

// A utility object that adapts a reader to apply the RC4 cypher as data is read.
struct CipherPassthroughIn<IN: Read> {
    stream: IN,
    cipher: Rc4,
    buffer: Vec<u8>
}

impl<IN: Read> Read for CipherPassthroughIn<IN> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.buffer.resize(buf.len(), 0);
        let out = self.stream.read(&mut self.buffer);
        if let Ok(size) = &out {
            self.buffer.resize(*size, 0);
            if let Err(err) = self.cipher.apply_keystream_b2b(&self.buffer, &mut buf[0..*size]) {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, anyhow::anyhow!("rc4 error {err}")))
            }
        }
        return out;
    }
}

impl<IN: Read> CipherPassthroughIn<IN> {
    fn new(stream: IN, cipher: Rc4) -> Self {
        Self {
            stream,
            cipher,
            buffer: vec![]
        }
    }

    // Extract the last chunk read from the stream. This can be used to
    // recover less-than-chunk sized footer data that was appended.
    fn last_chunk(self) -> Vec<u8> {
        self.buffer
    }
}

pub fn unpack_stream<IN: Read, OUT: Write>(mut istream: IN, mut ostream: OUT,
    rc4_key_override: Option<Vec<u8>>) -> anyhow::Result<(Option<JsonMap>, Option<JsonMap>)>
{
    // unpack to output stream, return header / footer
    // First read and unpack the mandatory header. This will tell us the RC4 key
    // and optional header length.
    // Optional header and rest of document are RC4'd
    let (rc4_key, optional_header, _pos) = _unpack_header(&mut istream, rc4_key_override)
        .context("Could not unpack header")?;

    // Read / Unpack / Output the binary stream 1 block at a time.
    let cipher = Rc4::new_from_slice(&rc4_key).context("Invalid rc4 key")?;
    let mut bz = flate2::read::ZlibDecoder::new_with_buf(
        CipherPassthroughIn::new(istream, cipher),
        vec![0u8; BLOCK_SIZE]
    );

    let mut buffer = vec![0u8; BLOCK_SIZE];
    loop {
        let size = bz.read(&mut buffer).context("reading from compressed stream")?;
        if size == 0 {
            break;
        }
        ostream.write_all(&buffer[0..size]).context("writing output")?;
    }
    let last_chunk = bz.into_inner().last_chunk();

    // unused data will be the
    let footer_offset = last_chunk.len() - MANDATORY_FOOTER_SIZE;
    let mut mandatory_footer_raw = bytes::Bytes::copy_from_slice(&last_chunk[footer_offset..]);

    {
        if !mandatory_footer_raw.starts_with(FOOTER_MAGIC) {
            return Err(anyhow::anyhow!("Corrupt cart: Missing footer magic"));
        }
        mandatory_footer_raw.advance(FOOTER_MAGIC.len());
        if mandatory_footer_raw.get_u64_le() != RESERVED {
            return Err(anyhow::anyhow!("Corrupt cart: Reserved footer space not zeroed"));
        }
    }
    let _opt_footer_pos = mandatory_footer_raw.get_u64_le();
    let opt_footer_len = mandatory_footer_raw.get_u64_le() as usize;

    let opt_footer_offset = footer_offset - opt_footer_len;

    let mut optional_footer = None;
    if opt_footer_len > 0 {
        let mut cipher = Rc4::new_from_slice(&rc4_key)?;
        let mut optional_crypt = last_chunk[opt_footer_offset..(opt_footer_offset + opt_footer_len)].to_vec();
        cipher.try_apply_keystream(&mut optional_crypt)?;
        optional_footer = Some(serde_json::from_slice(&optional_crypt)?);
    }
    ostream.flush()?;
    return Ok((optional_header, optional_footer))
}


#[cfg(test)]
mod tests {
    use std::io::{SeekFrom, Seek};

    use crate::digesters::default_digesters;

    use super::{pack_stream, unpack_stream};

    #[test]
    fn round_trip() {
        let raw_data = std::include_bytes!("cart.rs");
        let input_cursor = std::io::Cursor::new(raw_data);

        let mut buffer = tempfile::tempfile().unwrap();
        pack_stream(input_cursor, &mut buffer, None, None, default_digesters(), None).unwrap();
        buffer.seek(SeekFrom::Start(0)).unwrap();

        let mut output = vec![];
        unpack_stream(buffer, &mut output, None).unwrap();

        assert_eq!(output, raw_data);
    }

    #[test]
    fn empty() {
        let raw_data = vec![];
        let input_cursor = std::io::Cursor::new(&raw_data);

        let mut buffer = tempfile::tempfile().unwrap();
        pack_stream(input_cursor, &mut buffer, None, None, default_digesters(), None).unwrap();
        buffer.seek(SeekFrom::Start(0)).unwrap();

        let mut output = vec![];
        unpack_stream(buffer, &mut output, None).unwrap();

        assert_eq!(output, raw_data);
    }
}
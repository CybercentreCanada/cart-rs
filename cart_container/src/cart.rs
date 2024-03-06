//! The functions that actually implement stream encoding and decoding of the cart container.
//! 
//! This module also makes public header processing functions to allow parsing of only 
//! header data without fully unpacking the file data.
//! 

use std::io::{Write, Read};
use bytes::{BufMut, Buf};
use rc4::{KeyInit, StreamCipher};

use crate::cipher::{CipherPassthroughIn, CipherPassthroughOut, DEFAULT_RC4_KEY, Rc4};
use crate::digesters::Digester;
use crate::error::{Result, CartError};

/// Alias for a serde mapping cart will accept for metadata.
pub type JsonMap = serde_json::Map<String, serde_json::Value>;


// Constants regarding header and footer encoding
const MAJOR_VERSION: i16 = 1;
const MANDATORY_HEADER_SIZE: usize = 38;
const MANDATORY_FOOTER_SIZE: usize = 8 * 3 + 4;
pub (crate) const BLOCK_SIZE: usize = 64 * 1024;
const HEADER_MAGIC: &[u8; 4] = b"CART";
const FOOTER_MAGIC: &[u8; 4] = b"TRAC";
const RESERVED: u64 = 0;


/// Encoding function for cart format.
pub fn pack_stream<IN: Read, OUT: Write>(mut istream: IN, mut ostream: OUT,
    optional_header: Option<JsonMap>, optional_footer: Option<JsonMap>,
    mut digesters: Vec<Box<dyn Digester>>, rc4_key_override: Option<Vec<u8>>) -> Result<()>
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
        let mut cipher = Rc4::new_from_slice(&rc4_key)?;
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
            return Err(CartError::header_encoding())
        }
        header
    })?;

    // Write optional header
    if let Some(buffer) = opt_header_crypt {
        pos += buffer.len() as u64;
        ostream.write_all(&buffer)?;
    };

    // Create a zlib processor which will write its output to the passthrough
    // processor which will rc4 it before writing to the output stream
    let mut bz = flate2::write::ZlibEncoder::new(
        CipherPassthroughOut::new(&mut ostream, &rc4_key)?,
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
            digest.update(&buffer[0..bytes_read]);
        }

        // compress and then cipher any resulting output blocks
        bz.write_all(&buffer[0..bytes_read])?;
    }

    // Finish any remaining data in compressor
    pos += bz.total_out();
    bz.finish()?;

    // insert any requests digests into the optional footer.
    let optional_footer = if digesters.is_empty() {
        optional_footer
    } else {
        let mut optional_footer = optional_footer.unwrap_or_default();
        for mut digest in digesters {
            optional_footer.insert(digest.name(), serde_json::Value::String(digest.finish()));
        }
        Some(optional_footer)
    };

    // Write the optional footer if found
    let (footer_pos, footer_len) = if let Some(footer) = optional_footer {
        let opt_footer_pos = pos;
        let mut opt_footer_buffer = serde_json::to_vec(&footer)?;
        let mut cipher = Rc4::new_from_slice(&rc4_key)?;
        cipher.try_apply_keystream(&mut opt_footer_buffer)?;
        let opt_footer_len = opt_footer_buffer.len() as u64;
        ostream.write_all(&opt_footer_buffer)?;
        (opt_footer_pos, opt_footer_len)
    } else {
        (0, 0)
    };

    // Write the mandatory footer
    ostream.write_all(&{
        // Build the header in a buffer first
        let mut footer = vec![];
        footer.reserve(MANDATORY_FOOTER_SIZE);
        footer.put_slice(FOOTER_MAGIC); // MAGIC
        footer.put_u64_le(RESERVED); // Reserved
        footer.put_u64_le(footer_pos);
        footer.put_u64_le(footer_len);

        // Check the footer, and write it
        if footer.len() != MANDATORY_FOOTER_SIZE {
            return Err(CartError::footer_encoding())
        }
        footer
    })?;
    ostream.flush()?;
    return Ok(())
}

/// Decode and check only the mandatory parts of the header
///
/// This returns the rc4 key, the size of the optional header, and how many bytes have been read.
/// This method is only useful if you want to peek at the header information without parsing the 
/// entire file.
pub fn unpack_required_header<IN: Read>(mut istream: IN, rc4_key_override: Option<Vec<u8>>)
    -> Result<(Vec<u8>, u64, u64)>
{
    let mut pos: u64 = 0;

    // Read and unpack the madatory header.
    let mut header_buffer = vec![0u8; MANDATORY_HEADER_SIZE];
    istream.read_exact(&mut header_buffer)?;
    pos += MANDATORY_HEADER_SIZE as u64;
    let mut header_buffer = bytes::Bytes::from(header_buffer);

    // Check fixed value fields
    {
        if !header_buffer.starts_with(HEADER_MAGIC) {
            return Err(CartError::header_corrupt())
        }
        header_buffer.advance(HEADER_MAGIC.len());
        if header_buffer.get_i16_le() != MAJOR_VERSION {
            return Err(CartError::header_corrupt())
        }
        if header_buffer.get_u64_le() != RESERVED {
            return Err(CartError::header_corrupt())
        }
    }

    // Read the dynamic values fields
    let rc4_key = header_buffer.copy_to_bytes(16);
    let opt_header_len = header_buffer.get_u64_le();

    // Swap out the rc4 key if a different one is being provided
    let rc4_key = match rc4_key_override {
        Some(key) => key,
        None => rc4_key.to_vec(),
    };

    return Ok((rc4_key, opt_header_len, pos))
}

/// Decode and check the entire header, including the optional metadata
/// This method is only useful if you want to peek at the header information without parsing the entire file.
pub fn unpack_header<IN: Read>(mut istream: IN, rc4_key_override: Option<Vec<u8>>)
    -> Result<(Vec<u8>, Option<JsonMap>, u64)>
{
    let (rc4_key, opt_header_len, mut pos) = unpack_required_header(&mut istream, rc4_key_override)?;
    // Read and unpack any optional header.
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

/// Decode function for cart formatted data.
pub fn unpack_stream<IN: Read, OUT: Write>(mut istream: IN, mut ostream: OUT,
    rc4_key_override: Option<Vec<u8>>) -> Result<(Option<JsonMap>, Option<JsonMap>)>
{
    // unpack to output stream, return header / footer
    // First read and unpack the mandatory header. This will tell us the RC4 key
    // and optional header length.
    // Optional header and rest of document are RC4'd
    let (rc4_key, optional_header, _pos) = unpack_header(&mut istream, rc4_key_override)?;

    // Read / Unpack / Output the binary stream 1 block at a time.
    let cipher = Rc4::new_from_slice(&rc4_key)?;
    let mut bz = flate2::read::ZlibDecoder::new_with_buf(
        CipherPassthroughIn::new(istream, cipher),
        vec![0u8; BLOCK_SIZE]
    );

    let mut buffer = vec![0u8; BLOCK_SIZE];
    loop {
        let size = bz.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        ostream.write_all(&buffer[0..size])?;
    }
    let last_chunk = bz.into_inner().last_chunk();

    // unused data will be the
    let footer_offset = last_chunk.len() - MANDATORY_FOOTER_SIZE;
    let mut mandatory_footer_raw = bytes::Bytes::copy_from_slice(&last_chunk[footer_offset..]);

    {
        if !mandatory_footer_raw.starts_with(FOOTER_MAGIC) {
            return Err(CartError::footer_corrupt());
        }
        mandatory_footer_raw.advance(FOOTER_MAGIC.len());
        if mandatory_footer_raw.get_u64_le() != RESERVED {
            return Err(CartError::footer_corrupt());
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

    use md5::Digest;

    use crate::cart::{JsonMap, MANDATORY_HEADER_SIZE};
    use crate::digesters::default_digesters;

    use super::{pack_stream, unpack_stream};

    #[test]
    fn round_trip_headerless() {
        let raw_data = std::include_bytes!("cart.rs");
        let input_cursor = std::io::Cursor::new(raw_data);

        let mut buffer = tempfile::tempfile().unwrap();
        pack_stream(input_cursor, &mut buffer, None, None, vec![], None).unwrap();
        buffer.seek(SeekFrom::Start(0)).unwrap();

        let mut output = vec![];
        let (header, footer) = unpack_stream(buffer, &mut output, None).unwrap();

        assert!(header.is_none());
        assert!(footer.is_none());

        assert_eq!(output, raw_data);
    }

    #[test]
    fn round_trip() {
        let raw_data = std::include_bytes!("cart.rs");
        let input_cursor = std::io::Cursor::new(raw_data);

        let mut buffer = tempfile::tempfile().unwrap();

        let mut original_header = JsonMap::new();
        original_header.insert("abc".to_owned(), serde_json::to_value("123").unwrap());

        let mut original_footer = JsonMap::new();
        original_footer.insert("xyz".to_owned(), serde_json::to_value("999999999999999").unwrap());

        pack_stream(
            input_cursor,
            &mut buffer,
            Some(original_header.clone()),
            Some(original_footer.clone()),
            default_digesters(),
            None
        ).unwrap();
        buffer.seek(SeekFrom::Start(0)).unwrap();

        let mut output = vec![];
        let (header, footer) = unpack_stream(buffer, &mut output, None).unwrap();

        // Check header
        let header = header.unwrap();
        assert_eq!(header, original_header);

        // Check footer
        let footer = footer.unwrap();
        assert_eq!(footer.get("length"), Some(&serde_json::to_value(raw_data.len().to_string()).unwrap()));
        let mut hasher = sha2::Sha256::new();
        hasher.update(raw_data);
        assert_eq!(footer.get("sha256"), Some(&serde_json::to_value(format!("{:x}", hasher.finalize())).unwrap()));
        assert_eq!(footer.get("xyz"), Some(&serde_json::to_value("999999999999999").unwrap()));

        // Check payload
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

    #[test]
    fn custom_key() {
        let raw_data = std::include_bytes!("cart.rs");
        let input_cursor = std::io::Cursor::new(raw_data);

        let custom_key = vec![0x01u8; 16];


        let mut buffer = tempfile::tempfile().unwrap();
        pack_stream(input_cursor, &mut buffer, None, None, vec![], Some(custom_key.clone())).unwrap();
        buffer.seek(SeekFrom::Start(0)).unwrap();

        // Fail to open it with normal key
        let mut output = vec![];
        assert!(unpack_stream(&mut buffer, &mut output, None).is_err());
        buffer.seek(SeekFrom::Start(0)).unwrap();

        // Open with custom key
        let mut output = vec![];
        let (header, footer) = unpack_stream(buffer, &mut output, Some(custom_key)).unwrap();

        assert!(header.is_none());
        assert!(footer.is_none());

        assert_eq!(output, raw_data);
    }

    #[test]
    fn incomplete_data() {
        let raw_data = std::include_bytes!("cart.rs");
        let input_cursor = std::io::Cursor::new(raw_data);

        let mut buffer = tempfile::tempfile().unwrap();
        pack_stream(input_cursor, &mut buffer, None, None, vec![], None).unwrap();
        buffer.seek(SeekFrom::Start(0)).unwrap();
        let len = buffer.metadata().unwrap().len();

        // Truncate the buffer part way through the footer
        buffer.set_len(len - 2).unwrap();

        // make sure the unpack call returns an error rather than calling panic
        let mut output = vec![];
        assert!(unpack_stream(&mut buffer, &mut output, None).is_err());
        buffer.seek(SeekFrom::Start(0)).unwrap();

        // Truncate the buffer half way through
        buffer.set_len(len/2).unwrap();

        // make sure the unpack call returns an error rather than calling panic
        assert!(unpack_stream(&mut buffer, &mut output, None).is_err());
        buffer.seek(SeekFrom::Start(0)).unwrap();

        // Truncate even the header
        buffer.set_len(MANDATORY_HEADER_SIZE as u64 - 1).unwrap();
        assert!(unpack_stream(&mut buffer, &mut output, None).is_err());
    }

    #[test]
    fn conflicting_footer_data() {
        let raw_data = std::include_bytes!("cart.rs");
        let mut output = vec![];

        let mut output_metadata = super::JsonMap::new();
        output_metadata.insert("md5".to_owned(), "report.md5".into()); // String intod )o `serde_json::Value`
        output_metadata.insert("sha1".to_owned(), "report.sha1".into());
        output_metadata.insert("sha256".to_owned(), "report.sha256".into());
        output_metadata.insert("sha384".to_owned(), "report.sha384".into());
        output_metadata.insert("sha512".to_owned(), "report.sha512".into());
        output_metadata.insert("entropy".to_owned(), serde_json::Value::from(5.0f32)); // `f32`
        output_metadata.insert("file".to_owned(), "filecmd".into());

        pack_stream(
            std::io::Cursor::new(raw_data), // Cursor wrapping the vec of data
            &mut output, // Cursor wrapping empty vec
            None, // Optional header, tried this for the metadata
            Some(output_metadata), // Optional footer
            default_digesters(),
            None, // Rc4 key override, not used
        ).unwrap();

        let mut unpacked = vec![];

        let (header, footer) = unpack_stream(std::io::Cursor::new(output), &mut unpacked, None).unwrap();

        assert!(header.is_none()); // nothing should be added
        assert_eq!(unpacked, raw_data); // data should be preserved
        let footer = footer.unwrap(); // there must be a footer
        assert_ne!(footer["md5"], "report.md5"); // this should be overwritten with the real md5
        assert_eq!(footer["entropy"], serde_json::json!(5.0)); // this won't be effected by the digester
    }
}
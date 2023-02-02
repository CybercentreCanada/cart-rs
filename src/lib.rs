///
/// The CaRT file format is used to store/transfer malware and it's associated metadata.
/// It neuters the malware so it cannot be executed and encrypts it so anti-virus software
/// cannot flag the CaRT file as malware.
///
/// The functions, structs, and constants in the root of the package prefixed with `cart`
/// are all exported to build a c library.
///
/// An interfaces more suitable for calling from rust is in the [cart] module.
///

use std::ffi::c_char;
use std::ptr::{null, null_mut};

use cart::{JsonMap, unpack_header};
use cart::{pack_stream, unpack_stream};
use digesters::default_digesters;
use libc::c_void;

use crate::cart::unpack_required_header;

mod cipher;
pub mod cart;
pub mod digesters;

/// Error code set when a call completes without errors
pub const CART_NO_ERROR: u32 = 0;
/// Error code when a string argument could not be parsed
pub const CART_ERROR_BAD_ARGUMENT_STR: u32 = 1;
/// Error code when an input file could not be opened
pub const CART_ERROR_OPEN_FILE_READ: u32 = 2;
/// Error code when an output file could not be opened
pub const CART_ERROR_OPEN_FILE_WRITE: u32 = 3;
/// Error code when input json could not be parsed
pub const CART_ERROR_BAD_JSON_ARGUMENT: u32 = 5;
/// Error code when an error occurs processing the input data
pub const CART_ERROR_PROCESSING: u32 = 6;

/// Helper function to convert a c string with a path into a file object
fn _open(path: *const c_char, read: bool) -> Result<std::fs::File, u32> {
    // Check for null values
    if path == null() {
        return Err(CART_ERROR_BAD_ARGUMENT_STR)
    }

    // Wrap the c strings in something safer
    let path = unsafe { std::ffi::CStr::from_ptr(path) };

    // Make sure the input strings are valid utf-8
    let path = match path.to_str() {
        Ok(path) => path,
        Err(_) => return Err(CART_ERROR_BAD_ARGUMENT_STR),
    };

    if read {
        match std::fs::File::open(path) {
            Ok(file) => Ok(file),
            Err(_) => Err(CART_ERROR_OPEN_FILE_READ),
        }
    } else {
        match std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(path) {
            Ok(file) => Ok(file),
            Err(_) => Err(CART_ERROR_OPEN_FILE_WRITE),
        }
    }
}

/// Helper function to load a c string into a json map
fn _ready_json(header_json: *const c_char) -> Result<Option<JsonMap>, u32> {
    if header_json == null() {
        Ok(None)
    }  else {
        // Build a length tracked string from a null terminated string
        let header_json = unsafe { std::ffi::CStr::from_ptr(header_json) };

        // Make sure the content of the string is utf-8
        match header_json.to_str() {
            Ok(header) => {
                // Parse json out of the string
                match serde_json::from_str(header){
                    Ok(header) => Ok(Some(header)),
                    Err(_) => return Err(CART_ERROR_BAD_JSON_ARGUMENT),
                }
            },
            Err(_) => return Err(CART_ERROR_BAD_ARGUMENT_STR),
        }
    }
}


/// Cart encode a file from disk into a new file.
///
/// Encode a file in the cart format using default parameters for all optional parameters.
/// The output file will be truncated if it already exists.
/// The header json should be a json encoded string with a mapping of key value pairs.
#[no_mangle]
pub extern "C" fn cart_pack_file_default(
    input_path: *const c_char,
    output_path: *const c_char,
    header_json: *const c_char,
) -> u32 {
    // Open input file
    let input_file = match _open(input_path, true) {
        Ok(file) => file,
        Err(err) => return err,
    };
    let input_file = std::io::BufReader::new(input_file);

    // Open output file
    let output_file = match _open(output_path, false) {
        Ok(file) => file,
        Err(err) => return err,
    };

    // Load in the header json if any is set.
    let header_json = match _ready_json(header_json) {
        Ok(header) => header,
        Err(err) => return err,
    };

    // Process stream
    let result = pack_stream(
        input_file,
        output_file,
        header_json,
        None,
        default_digesters(),
        None
    );

    match result {
        Ok(_) => CART_NO_ERROR,
        Err(_) => CART_ERROR_PROCESSING,
    }
}


struct CFileReader {
    stream: *mut libc::FILE
}

impl std::io::Read for CFileReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        unsafe {
            let ptr = buf.as_mut_ptr() as *mut c_void;
            let size = libc::fread(ptr, 1, buf.len(), self.stream);
            if size == 0 {
                if libc::feof(self.stream) != 0 {
                    return Ok(size)
                } else {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, anyhow::anyhow!("Failed to read from raw file handle")))
                }
            } else {
                return Ok(size)
            }
        };
    }
}

impl CFileReader {
    fn new(stream: *mut libc::FILE) -> Self {
        Self{stream}
    }
}

struct CFileWriter {
    stream: *mut libc::FILE
}

impl std::io::Write for CFileWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        unsafe {
            let ptr = buf.as_ptr() as *const c_void;
            Ok(libc::fwrite(ptr, 1, buf.len(), self.stream))
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if unsafe {libc::fflush(self.stream)} == 0 {
            Ok(())
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::InvalidData, anyhow::anyhow!("Failed to flush raw file handle")))
        }
    }
}

/// Cart encode between open libc file handles.
///
/// Encode a file in the cart format using default parameters for all optional parameters.
/// The input handle must be open for reading, the output handle must be open for writing.
/// The header json should be a json encoded string with a mapping of key value pairs.
#[no_mangle]
pub extern "C" fn cart_pack_stream_default(
    input_stream: *mut libc::FILE,
    output_stream: *mut libc::FILE,
    header_json: *const c_char,
) -> u32 {
    // Open input file
    let input_file = CFileReader{stream: input_stream};
    let input_file = std::io::BufReader::new(input_file);

    // Load in the header json if any is set.
    let header_json = match _ready_json(header_json) {
        Ok(header) => header,
        Err(err) => return err,
    };

    // Process stream
    let result = pack_stream(
        input_file,
        CFileWriter{stream: output_stream},
        header_json,
        None,
        default_digesters(),
        None
    );

    match result {
        Ok(_) => CART_NO_ERROR,
        Err(_) => CART_ERROR_PROCESSING,
    }
}

/// A struct returned from encoding functions that may return a buffer.
///
/// The buffer `packed` should only be set if the `error` field is set to [CART_NO_ERROR].
/// Buffers behind this structure can be released using the [cart_free_pack_result] function.
#[repr(C)]
pub struct CartPackResult {
    error: u32,
    packed: *mut u8,
    packed_size: u64,
}

impl CartPackResult {
    fn new_err(error: u32) -> Self {
        Self {
            error,
            packed: null_mut(),
            packed_size: 0,
        }
    }

    fn new(data: Vec<u8>) -> Self {
        let mut data = data.into_boxed_slice();
        let out = Self {
            error: CART_NO_ERROR,
            packed: data.as_mut_ptr(),
            packed_size: data.len() as u64,
        };
        std::mem::forget(data);
        out
    }
}

/// Cart encode a buffer.
///
/// Encode a file in the cart format using default parameters for all optional parameters.
/// The header json should be a json encoded string with a mapping of key value pairs.
#[no_mangle]
pub extern "C" fn cart_pack_data_default(
    input_buffer: *const c_char,
    input_buffer_size: usize,
    header_json: *const c_char,
) -> CartPackResult {
    // cast c pointer to rust slice
    let input_data = unsafe {
        let input_buffer = input_buffer as *const u8;
        std::slice::from_raw_parts(input_buffer, input_buffer_size)
    };

    // Load in the header json if any is set.
    let header_json = match _ready_json(header_json) {
        Ok(header) => header,
        Err(err) => return CartPackResult::new_err(err),
    };

    // capture output data in vector
    let mut output_buffer = vec![];

    // Process stream
    let result = pack_stream(
        input_data,
        &mut output_buffer,
        header_json,
        None,
        default_digesters(),
        None
    );

    match result {
        Ok(_) => CartPackResult::new(output_buffer),
        Err(_) => CartPackResult::new_err(CART_ERROR_PROCESSING),
    }
}

/// A struct returned from decoding functions that may return a buffer.
///
/// Which buffers have a value depends on the semantics of the function returning it.
/// Buffers should only be set if the `error` field is set to [CART_NO_ERROR].
/// Buffers behind this structure can be released using the [cart_free_unpack_result] function.
#[repr(C)]
pub struct CartUnpackResult {
    error: u32,
    body: *mut u8,
    body_size: u64,
    header_json: *mut u8,
    header_json_size: u64,
    footer_json: *mut u8,
    footer_json_size: u64,
}

impl CartUnpackResult {
    fn new_err(error: u32) -> Self {
        Self {
            error,
            body: std::ptr::null_mut(),
            body_size: 0,
            header_json: std::ptr::null_mut(),
            header_json_size: 0,
            footer_json: std::ptr::null_mut(),
            footer_json_size: 0,
        }
    }

    fn str_to_ptr(mut data: Vec<u8>) -> (*mut u8, u64) {
        if !data.is_empty() {
            data.push(0);
        }
        Self::data_to_ptr(data)
    }

    fn data_to_ptr(data: Vec<u8>) -> (*mut u8, u64) {
        if data.is_empty() {
            (null_mut(), 0)
        } else {
            let mut data = data.into_boxed_slice();
            let ptr = data.as_mut_ptr();
            let len = data.len() as u64;
            std::mem::forget(data);
            (ptr, len)
        }
    }

    fn new(body: Vec<u8>, header: Option<JsonMap>, footer: Option<JsonMap>) -> Self {
        let mut out = Self::new_meta(header, footer);

        let (ptr, len) = Self::data_to_ptr(body);

        out.body = ptr;
        out.body_size = len;

        return out;
    }

    fn new_meta(header: Option<JsonMap>, footer: Option<JsonMap>) -> Self {
        let header_data = match header {
            Some(header) => serde_json::to_vec(&header).unwrap_or_default(),
            None => Default::default(),
        };
        let footer_data = match footer {
            Some(footer) => serde_json::to_vec(&footer).unwrap_or_default(),
            None => Default::default(),
        };

        let (header_json, header_json_size) = Self::str_to_ptr(header_data);
        let (footer_json, footer_json_size) = Self::str_to_ptr(footer_data);

        Self {
            error: CART_NO_ERROR,
            body: std::ptr::null_mut(),
            body_size: 0,
            header_json,
            header_json_size,
            footer_json,
            footer_json_size,
        }
    }
}

/// Decode a cart encoded file into a new file.
///
/// The decoded file body is written to the output file and is not set the returned struct.
/// The output file will be truncated if it already exists.
#[no_mangle]
pub extern "C" fn cart_unpack_file(
    input_path: *const c_char,
    output_path: *const c_char,
) -> CartUnpackResult {
    // Open input file
    let input_file = match _open(input_path, true) {
        Ok(file) => file,
        Err(err) => return CartUnpackResult::new_err(err),
    };
    let input_file = std::io::BufReader::new(input_file);

    // Open output file
    let output_file = match _open(output_path, false) {
        Ok(file) => file,
        Err(err) => return CartUnpackResult::new_err(err),
    };

    // Process stream
    let result = unpack_stream(
        input_file,
        output_file,
        None
    );

    match result {
        Ok((header, footer)) => {
            CartUnpackResult::new_meta(header, footer)
        },
        Err(_) => CartUnpackResult::new_err(CART_ERROR_PROCESSING),
    }
}

/// Decode cart data from an open libc file into another.
///
/// The decoded file body is written to the output and is not set the returned struct.
/// The input handle must be open for reading, the output handle must be open for writing.
#[no_mangle]
pub extern "C" fn cart_unpack_stream(
    input_stream: *mut libc::FILE,
    output_stream: *mut libc::FILE,
) -> CartUnpackResult {
    // Wrap the input file object
    let input_stream = CFileReader {stream: input_stream};
    let input_file = std::io::BufReader::new(input_stream);
    let output_file = CFileWriter { stream: output_stream };

    // Process stream
    let result = unpack_stream(
        input_file,
        output_file,
        None
    );

    match result {
        Ok((header, footer)) => {
            CartUnpackResult::new_meta(header, footer)
        },
        Err(_) => CartUnpackResult::new_err(CART_ERROR_PROCESSING),
    }
}

/// Decode cart data from a buffer.
#[no_mangle]
pub extern "C" fn cart_unpack_data (
    input_buffer: *const c_char,
    input_buffer_size: usize
) -> CartUnpackResult {
    // cast c pointer to rust slice
    let input_data = unsafe {
        let input_buffer = input_buffer as *const u8;
        std::slice::from_raw_parts(input_buffer, input_buffer_size)
    };

    // Capture output in buffer
    let mut output = vec![];

    // Process stream
    let result = unpack_stream(
        input_data,
        &mut output,
        None
    );

    match result {
        Ok((header, footer)) => {
            CartUnpackResult::new(output, header, footer)
        },
        Err(_) => CartUnpackResult::new_err(CART_ERROR_PROCESSING),
    }
}

/// Test if the file at a given path contains cart data.
#[no_mangle]
pub extern "C" fn cart_is_file_cart (
    input_path: *const c_char,
) -> bool {
    // Open input file
    let input_file = match _open(input_path, true) {
        Ok(file) => file,
        Err(_) => return false,
    };

    unpack_required_header(input_file, None).is_ok()
}

/// Test if the given file object contains cart data.
///
/// The file handle is read from and is not reset to its original location.
#[no_mangle]
pub extern "C" fn cart_is_stream_cart (
    stream: *mut libc::FILE,
) -> bool {
    // Open input file
    let input_file = CFileReader::new(stream);
    unpack_required_header(input_file, None).is_ok()
}

/// Test if the given buffer contains cart data.
#[no_mangle]
pub extern "C" fn cart_is_data_cart (
    data: *const c_char,
    data_size: usize,
) -> bool {
    // cast c pointer to rust slice
    let input_data = unsafe {
        let input_buffer = data as *const u8;
        std::slice::from_raw_parts(input_buffer, data_size)
    };
    unpack_required_header(input_data, None).is_ok()
}

/// Open the cart file at the given path and read out its metadata.
///
/// In the returned struct only the header buffer will contain data.
#[no_mangle]
pub extern "C" fn cart_get_file_metadata_only(
    input_path: *const c_char
) -> CartUnpackResult {
    // Open input file
    let input_file = match _open(input_path, true) {
        Ok(file) => file,
        Err(err) => return CartUnpackResult::new_err(err),
    };

    match unpack_header(input_file, None) {
        Ok((_, header, _)) => CartUnpackResult::new_meta(header, None),
        Err(_) => CartUnpackResult::new_err(CART_ERROR_PROCESSING),
    }
}

/// Read header metadata only from a cart file object.
///
/// In the returned struct only the header buffer will contain data.
#[no_mangle]
pub extern "C" fn cart_get_stream_metadata_only(
    stream: *mut libc::FILE
) -> CartUnpackResult {
    let input_file = CFileReader::new(stream);

    match unpack_header(input_file, None) {
        Ok((_, header, _)) => CartUnpackResult::new_meta(header, None),
        Err(_) => CartUnpackResult::new_err(CART_ERROR_PROCESSING),
    }
}

/// Read header metadata only from a buffer of cart data.
///
/// In the returned struct only the header buffer will contain data.
#[no_mangle]
pub extern "C" fn cart_get_data_metadata_only(
    data: *const c_char,
    data_size: usize
) -> CartUnpackResult {
    let input_data = unsafe {
        let input_buffer = data as *const u8;
        std::slice::from_raw_parts(input_buffer, data_size)
    };
    match unpack_header(input_data, None) {
        Ok((_, header, _)) => CartUnpackResult::new_meta(header, None),
        Err(_) => CartUnpackResult::new_err(CART_ERROR_PROCESSING),
    }
}


/// Release any resources behind a [CartUnpackResult] struct.
///
/// This function should be safe to call even if the struct has no data.
/// This function should be safe to call repeatedly on the same struct.
#[no_mangle]
pub extern "C" fn cart_free_unpack_result(mut buf: CartUnpackResult) {
    unsafe {
        if buf.body != null_mut() {
            let s = std::slice::from_raw_parts_mut(buf.body, buf.body_size as usize);
            let s = s.as_mut_ptr();
            drop(Box::from_raw(s));
            buf.body = null_mut();
            buf.body_size = 0;
        }
        if buf.header_json != null_mut() {
            let s = std::slice::from_raw_parts_mut(buf.header_json, buf.header_json_size as usize);
            let s = s.as_mut_ptr();
            drop(Box::from_raw(s));
            buf.header_json = null_mut();
            buf.header_json_size = 0;
        }
        if buf.footer_json != null_mut() {
            let s = std::slice::from_raw_parts_mut(buf.footer_json, buf.footer_json_size as usize);
            let s = s.as_mut_ptr();
            drop(Box::from_raw(s));
            buf.footer_json = null_mut();
            buf.footer_json_size = 0;
        }
    }
}

/// Release any resources behind a [CartPackResult] struct.
///
/// This function should be safe to call even if the struct has no data.
/// This function should be safe to call repeatedly on the same struct.
#[no_mangle]
pub extern "C" fn cart_free_pack_result(mut buf: CartPackResult) {
    unsafe {
        if buf.packed != null_mut() {
            let s = std::slice::from_raw_parts_mut(buf.packed, buf.packed_size as usize);
            let s = s.as_mut_ptr();
            drop(Box::from_raw(s));
            buf.packed = null_mut();
            buf.packed_size = 0;
        }
    }
}

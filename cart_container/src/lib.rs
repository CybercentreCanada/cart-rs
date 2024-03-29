//! The CaRT file format is used to store/transfer malware and it's associated metadata.
//!
//! It neuters the malware so it cannot be executed and encrypts it so anti-virus software
//! cannot flag the CaRT file as malware. This encryption is intentionally weak and 
//! only intended for obfuscation.
//! 
//! File content is also compressed.
//!
//! ```rust
//! use cart_container::{pack_stream, JsonMap, unpack_stream, digesters::default_digesters};
//! use tempfile;
//!
//! // A file to encode
//! let input_file = "./Cargo.toml";
//! let metadata_json: JsonMap = [("hello".to_owned(), serde_json::json!("world"))].into_iter().collect();
//! let carted_file = tempfile::NamedTempFile::new().unwrap();
//! let output_file = tempfile::NamedTempFile::new().unwrap();
//!
//! // Encode file
//! pack_stream(
//!     std::fs::File::open(input_file).unwrap(),
//!     carted_file.as_file(),
//!     Some(metadata_json.clone()),
//!     None,
//!     default_digesters(),
//!     None
//! ).unwrap();
//!
//! // Decode file
//! let (header, footer) = unpack_stream(
//!     carted_file.reopen().unwrap(),
//!     output_file.as_file(),
//!     None
//! ).unwrap();
//!
//! let original_content = std::fs::read(input_file).unwrap();
//! // the content should be preserved
//! assert_eq!(std::fs::read(output_file.path()).unwrap(), original_content);
//! // the header should be exactly the same
//! assert_eq!(header.unwrap(), metadata_json);
//! // the footer should contain all the digests. we used the default set which includes length
//! assert_eq!(footer.unwrap().get("length"), Some(&serde_json::Value::from(original_content.len().to_string())));
//!
//! ```
#![warn(missing_docs, non_ascii_idents, trivial_numeric_casts,
    unused_crate_dependencies, noop_method_call, single_use_lifetimes, trivial_casts,
    unused_lifetimes, nonstandard_style, variant_size_differences)]
// #![warn(clippy::pedantic)]
#![deny(keyword_idents)]
#![allow(clippy::needless_return)]


mod cipher;

pub mod error;
pub mod cart;
pub mod digesters;

pub use cart::{pack_stream, unpack_stream, JsonMap};
pub use digesters::default_digesters;

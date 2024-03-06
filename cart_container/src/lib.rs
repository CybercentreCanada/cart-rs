//! The CaRT file format is used to store/transfer malware and it's associated metadata.
//!
//! It neuters the malware so it cannot be executed and encrypts it so anti-virus software
//! cannot flag the CaRT file as malware.
//!
//! The functions, structs, and constants in the root of the package prefixed with `cart`
//! are all exported to build a c library.
//!
//! ```c
//! #include "cart.h"
//! #include <string.h>
//!
//! int main(char** argv, int argn) {
//!     // A file to encode
//!     char* input_file = "./cart.h";
//!     char* metadata_json = "{\"hello\": \"world\"}";
//!     char* carted_file = "./cart.h.cart";
//!     char* output_file = "./cart_copy.h";
//!
//!     // Encode file
//!     if(CART_NO_ERROR != cart_pack_file_default(input_file, carted_file, metadata_json)) {
//!         return 1;
//!     }
//!
//!     // Decode file
//!     CartUnpackResult result = cart_unpack_file(carted_file, output_file);
//!     if(result.error != CART_NO_ERROR) {
//!         return 2;
//!     }
//!
//!     cart_free_unpack_result(result);
//! }
//! ```
//!
//! An interfaces more suitable for calling from rust is in the [cart] module.
//! Note that the crate is named 'cart_container' but the library is exported as 'cart'.
//!
//! ```rust
//! use anyhow::Result;
//! use ::cart::cart::{pack_stream, JsonMap, unpack_stream};
//! use tempfile;
//!
//! fn main() -> Result<()> {
//!     // A file to encode
//!     let input_file = "./readme.md";
//!     let metadata_json: JsonMap = [("hello".to_owned(), serde_json::json!("world"))].into_iter().collect();
//!     let carted_file = tempfile::NamedTempFile::new()?;
//!     let output_file = tempfile::NamedTempFile::new()?;
//!
//!     // Encode file
//!     pack_stream(
//!         std::fs::File::open(input_file)?,
//!         carted_file.as_file(),
//!         Some(metadata_json.clone()),
//!         None,
//!         cart::digesters::default_digesters(),
//!         None
//!     )?;
//!
//!     // Decode file
//!     let (header, footer) = unpack_stream(
//!         carted_file.reopen()?,
//!         output_file.as_file(),
//!         None
//!     )?;
//!
//!     let original_content = std::fs::read(input_file)?;
//!     // the content should be preserved
//!     assert_eq!(std::fs::read(output_file.path())?, original_content);
//!     // the header should be exactly the same
//!     assert_eq!(header.unwrap(), metadata_json);
//!     // the footer should contain all the digests. we used the default set which includes length
//!     assert_eq!(footer.unwrap().get("length"), Some(&serde_json::Value::from(original_content.len().to_string())));
//!
//!     Ok(())
//! }
//! ```
#![warn(missing_docs, non_ascii_idents, trivial_numeric_casts,
    unused_crate_dependencies, noop_method_call, single_use_lifetimes, trivial_casts,
    unused_lifetimes, nonstandard_style, variant_size_differences)]
#![deny(keyword_idents)]
// #![warn(clippy::missing_docs_in_private_items)]
#![allow(clippy::needless_return)]
// #![allow(clippy::needless_return, clippy::while_let_on_iterator, clippy::collapsible_else_if)]


mod cipher;

pub mod error;
pub mod cart;
pub mod digesters;

pub use cart::{pack_stream, unpack_stream, JsonMap};
pub use digesters::default_digesters;

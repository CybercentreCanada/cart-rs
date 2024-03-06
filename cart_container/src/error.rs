//! Error handling structures

/// Lightweight error type that contains only a pointer to more details.
#[derive(Debug)]
pub struct CartError(pub Box<CartErrorKind>);

/// Detailed error type that contains cause of error.
#[derive(Debug)]
pub enum CartErrorKind {
    /// Likely data corruption issue
    Rc4Stream,
    /// Parameter issue
    Rc4KeyLength,
    /// Should only be caused by library internal sanity checks 
    HeaderEncoding,
    /// Should only be caused by library internal sanity checks 
    FooterEncoding,
    /// Likely data corruption issue
    HeaderCorrupt,
    /// Likely data corruption issue
    FooterCorrupt,
    /// Data corruption or parameter issue
    MetadataEncoding(serde_json::Error),
    /// IO could be anything related to the input or output streams
    IO(std::io::Error),
}

impl std::fmt::Display for CartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use CartErrorKind::*;
        match self.0.as_ref() {
            Rc4Stream => f.write_str("The file body stream is corrupted or unreadable."),
            Rc4KeyLength => f.write_str("RC4 key must be 16 bytes."),
            HeaderEncoding => f.write_str("The header data could not be encoded."),
            FooterEncoding => f.write_str("The footer data could not be encoded."),
            HeaderCorrupt => f.write_str("The manditory header data was corrupt."),
            FooterCorrupt => f.write_str("The manditory footer data was corrupt."),
            MetadataEncoding(err) => f.write_fmt(format_args!("Header or footer metadata encoding error: {err}")),
            IO(err) => f.write_fmt(format_args!("An error occurred during an IO operation: {err}")),
        }
    }
}

impl std::error::Error for CartError {}

impl CartError {
    pub(crate) fn header_encoding() -> Self {
        Self(Box::new(CartErrorKind::HeaderEncoding))
    }
    pub(crate) fn footer_encoding() -> Self {
        Self(Box::new(CartErrorKind::FooterEncoding))
    }
    pub(crate) fn header_corrupt() -> Self {
        Self(Box::new(CartErrorKind::HeaderCorrupt))
    }
    pub(crate) fn footer_corrupt() -> Self {
        Self(Box::new(CartErrorKind::FooterCorrupt))
    }
}

impl From<rc4::cipher::InvalidLength> for CartError {
    fn from(_: rc4::cipher::InvalidLength) -> Self { Self(Box::new(CartErrorKind::Rc4KeyLength)) }
}

impl From<rc4::cipher::StreamCipherError> for CartError {
    fn from(_: rc4::cipher::StreamCipherError) -> Self { Self(Box::new(CartErrorKind::Rc4Stream)) }
}

impl From<std::io::Error> for CartError {
    fn from(value: std::io::Error) -> Self { Self(Box::new(CartErrorKind::IO(value))) }
}

impl From<serde_json::Error> for CartError {
    fn from(value: serde_json::Error) -> Self { Self(Box::new(CartErrorKind::MetadataEncoding(value))) }
}

/// Alias for result that always uses CartError
pub type Result<T> = std::result::Result<T, CartError>;
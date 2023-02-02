/// A module of helper objects to turn the RustCrypto implementation of RC4 into
/// a stream object.

use std::io::{Read, Write};
use anyhow::Context;
use rc4::{KeyInit, StreamCipher};

use crate::cart::BLOCK_SIZE;


/// Alias for the specific configuration of RC4 that cart uses.
pub (crate) type Rc4 = rc4::Rc4::<rc4::consts::U16>;

/// Our default passkey for rc4 is the first 8 digits of PI twice.
pub (crate) const DEFAULT_RC4_KEY: [u8; 16] = [
    0x03, 0x01, 0x04, 0x01, 0x05, 0x09, 0x02, 0x06,
    0x03, 0x01, 0x04, 0x01, 0x05, 0x09, 0x02, 0x06
];


/// A utility object that adapts a reader to apply the RC4 cypher as data is read.
/// A buffer of read data is preserved to allow access to trailing data after expected stream content is exhausted.
pub (crate) struct CipherPassthroughIn<IN: Read> {
    stream: IN,
    cipher: Rc4,
    buffer: Vec<u8>
}

impl<IN: Read> Read for CipherPassthroughIn<IN> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // make sure the intermediary buffer is the right size
        self.buffer.resize(buf.len(), 0);

        // Perform the underlying read
        let out = self.stream.read(&mut self.buffer);

        if let Ok(size) = &out {
            // Trim the buffer to frame actual content
            self.buffer.resize(*size, 0);

            // Apply the rc4 cipher pass and copy at the same time
            if let Err(err) = self.cipher.apply_keystream_b2b(&self.buffer, &mut buf[0..*size]) {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, anyhow::anyhow!("rc4 error {err}")))
            }
        }
        return out;
    }
}

impl<IN: Read> CipherPassthroughIn<IN> {
    pub fn new(stream: IN, cipher: Rc4) -> Self {
        Self {
            stream,
            cipher,
            buffer: vec![]
        }
    }

    // Extract the last chunk read from the stream. This can be used to
    // recover less-than-chunk sized footer data that was appended.
    pub fn last_chunk(self) -> Vec<u8> {
        self.buffer
    }
}


/// A utility object that adapts a writer to apply the RC4 cypher as data is written.
///
/// Since the content buffer as defined by the Write trait is const, we need to
/// use an intermediary buffer to apply the rc4.
pub (crate) struct CipherPassthroughOut<'a, OUT: Write> {
    cipher: Rc4,
    output: &'a mut OUT,
    buffer: Vec<u8>,
}

impl<'a, OUT: Write> Write for CipherPassthroughOut<'a, OUT> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Adjust buffer to fit
        self.buffer.resize(buf.len(), 0);

        // Apply rc4 pass and copy between buffers at the same time
        if let Err(err) = self.cipher.apply_keystream_b2b(buf, &mut self.buffer) {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, anyhow::anyhow!(err)))
        };

        // Call the underlying write operation
        self.output.write_all(&self.buffer[0..buf.len()])?;
        return Ok(buf.len());
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.output.flush()
    }
}

impl<'a, OUT: Write> CipherPassthroughOut<'a, OUT> {
    pub fn new(output: &'a mut OUT, rc4_key: &Vec<u8>) -> anyhow::Result<Self> {
        Ok(Self {
            cipher: Rc4::new_from_slice(&rc4_key).context("Bad RC4 Key")?,
            output,
            buffer: vec![0u8; BLOCK_SIZE]
        })
    }
}
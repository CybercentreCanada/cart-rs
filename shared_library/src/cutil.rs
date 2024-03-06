use std::ptr::null_mut;

/// A module for utility classes and functions for accessing values passed from or returned to c code.

use libc::c_void;


pub (crate) struct CFileReader {
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
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to read from raw file handle"))
                }
            } else {
                return Ok(size)
            }
        };
    }
}

impl CFileReader {
    pub fn new(stream: *mut libc::FILE) -> Result<Self, &'static str> {
        if stream == null_mut() {
            Err("Null is not a file stream.")
        } else {
            Ok(Self{stream})
        }
    }
}

pub (crate) struct CFileWriter {
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
            Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to flush raw file handle"))
        }
    }
}

impl CFileWriter {
    pub fn new(stream: *mut libc::FILE) -> Result<Self, &'static str> {
        if stream == null_mut() {
            Err("Null is not a file stream.")
        } else {
            Ok(Self{stream})
        }
    }
}
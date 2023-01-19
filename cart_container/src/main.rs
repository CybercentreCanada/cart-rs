// use std::io::{Write, Read};

fn main() {
    todo!();
//     // let raw = b"sonchudsogc.udosc.huonthusonch.usrod.usocedusocnh00000000000000000000000000unsoht.u";
//     let TAIL = b"abc123";
//     let raw = std::fs::read("/bin/bash").unwrap();

//     let mut buffer = vec![];

//     let mut compressor = flate2::write::ZlibEncoder::new(&mut buffer, flate2::Compression::fast());
//     let mut reader = std::io::Cursor::new(raw);
//     loop {
//         let mut buffer = vec![0u8; 1 << 10];
//         let bytes = reader.read(&mut buffer).unwrap();
//         if bytes == 0 {
//             break
//         }
//         compressor.write_all(&buffer[0..bytes]).unwrap();
//     }
//     compressor.finish().unwrap();

//     let raw = reader.into_inner();
//     println!("{} {}", raw.len(), buffer.len());
//     buffer.extend(TAIL);

//     // let mut decompress = flate2::Decompress::new(true);
//     // let mut reader = std::io::Cursor::new(buffer);
//     // let mut last_chunk: Vec<u8> = vec![];
//     // let mut output: Vec<u8> = vec![];
//     // loop {
//     //     let mut buffer = vec![0u8; 1 << 10];
//     //     let bytes = reader.read(&mut buffer).unwrap();
//     //     let mut chunk = vec![0u8; 1 << 10];
//     //     let status = decompress.decompress(&buffer[0..bytes], &mut chunk, flate2::FlushDecompress::None).unwrap();
//     //     last_chunk = buffer;
//     //     let new_bytes = decompress.total_out() as usize - output.len();
//     //     output.extend(&chunk[0..new_bytes]);
//     //     match status {
//     //         flate2::Status::Ok => {},
//     //         flate2::Status::BufError => todo!(),
//     //         flate2::Status::StreamEnd => break,
//     //     }
//     // }

//     let mut decompress = flate2::read::ZlibDecoder::new(LastChunkCatcher::new(std::io::Cursor::new(buffer)));

//     let mut output: Vec<u8> = vec![];
//     let mut working = vec![0u8; 64];
//     loop {
//         let x = decompress.read(&mut working).unwrap();
//         if x == 0 {
//             break
//         }
//         output.extend(&working[0..x]);
//     }

//     assert_eq!(output, raw);

//     let chunk_cacher = decompress.into_inner();
//     let last_chunk = chunk_cacher.chunk();
//     // decompress.flush().unwrap();
//     // let mut stream = decompress.into_inner();

//     // let size = stream.read_to_end(&mut working).unwrap();
//     assert!(last_chunk.ends_with(b"abc123"));
}



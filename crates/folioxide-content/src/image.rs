//! Images for content streams (ISO 32000-2 §8.9).
//!
//! M4 has the JPEG passthrough ([`jpeg`]): the JPEG file becomes the data of a `/DCTDecode`
//! image XObject unchanged, after a bounded header parse. PNG and pixel decoding arrive with
//! M7 (features `images` and `jpeg-decode`).

pub mod jpeg;

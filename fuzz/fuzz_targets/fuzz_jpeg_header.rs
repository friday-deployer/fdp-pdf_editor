//! Fuzz target `fuzz_jpeg_header`: the JPEG passthrough of visible signature appearances (M4
//! brief §4.7 "JPEG", decision D-17): `folioxide_content::image::jpeg::parse_header`, a single
//! bounded pass over the marker segments up to the first scan, and `image_xobject`, which
//! wraps the unchanged bytes in a `/DCTDecode` image XObject.
//!
//! The input is a JPEG file, so the committed `fixtures/images/*.jpg` are a useful seed corpus
//! as they are. On any input:
//! - nothing panics, overflows or hangs (the walk is linear: libFuzzer's own `-timeout` is the
//!   hang check);
//! - an accepted header is one the module documents as supported: SOI first, at most
//!   `MAX_JPEG_LEN` bytes, a non-zero size, 1 or 3 components of 8 bits, RGB component IDs
//!   only with 3 components;
//! - `image_xobject` agrees with `parse_header` (same info, or an error with the same code),
//!   keeps the bytes unchanged, and writes `/DecodeParms << /ColorTransform 0 >>` exactly when
//!   the IDs say RGB and no Adobe APP14 marker governs the transform;
//! - every refusal is `ErrorCode::Image` (malformed) or `ErrorCode::Unsupported`.
//!
//! Run with `cargo +nightly fuzz run fuzz_jpeg_header` from the repository root.

#![no_main]

use folioxide_content::image::jpeg;
use folioxide_syntax::{ErrorCode, StreamData};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match jpeg::parse_header(data) {
        Ok(info) => {
            assert!(data.starts_with(&[0xFF, 0xD8]));
            assert!(data.len() <= jpeg::MAX_JPEG_LEN);
            assert!(info.width > 0 && info.height > 0, "{info:?}");
            assert!(matches!(info.components, 1 | 3), "{info:?}");
            assert_eq!(info.bits_per_component, 8);
            assert!(!info.rgb_component_ids || info.components == 3, "{info:?}");

            let Ok((stream, again)) = jpeg::image_xobject(data.to_vec()) else {
                panic!("image_xobject refused a header parse_header accepted: {info:?}");
            };
            assert_eq!(again, info);
            assert!(matches!(&stream.data, StreamData::Encoded(bytes) if bytes == data));
            let dict = &stream.dict;
            assert_eq!(dict.get_int(b"Width"), Some(i64::from(info.width)));
            assert_eq!(dict.get_int(b"Height"), Some(i64::from(info.height)));
            assert_eq!(dict.get_int(b"BitsPerComponent"), Some(8));
            assert!(dict.get_name(b"Filter").is_some_and(|f| f == "DCTDecode"));
            let space = if info.components == 1 {
                "DeviceGray"
            } else {
                "DeviceRGB"
            };
            assert!(dict.get_name(b"ColorSpace").is_some_and(|cs| cs == space));
            let transform_0 = info.rgb_component_ids && info.adobe_transform.is_none();
            assert_eq!(dict.contains_key(b"DecodeParms"), transform_0, "{info:?}");
        }
        Err(err) => {
            let code = err.code();
            assert!(
                matches!(code, ErrorCode::Image | ErrorCode::Unsupported),
                "{err}"
            );
            match jpeg::image_xobject(data.to_vec()) {
                Ok(_) => panic!("image_xobject accepted a header parse_header refused: {err}"),
                Err(again) => assert_eq!(again.code(), code),
            }
        }
    }
});

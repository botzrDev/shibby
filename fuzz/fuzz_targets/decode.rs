#![no_main]

use libfuzzer_sys::fuzz_target;
use uat_core::{decode, AllowAll};

fuzz_target!(|data: &[u8]| {
    // Never panics. Ok only for well-formed frames; F1 violations must be Err.
    let _ = decode(data, &AllowAll);
});

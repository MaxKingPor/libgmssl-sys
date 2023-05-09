#![allow(non_camel_case_types)]

pub mod sm2;
pub use sm2::*;

pub use hex::*;
pub mod hex {
    extern "C" {
        pub fn hex_to_bytes(
            in_: *const u8,
            inlen: usize,
            out: *mut u8,
            outlen: *mut usize,
        ) -> isize;
    }
}

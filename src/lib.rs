#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub use aes_ctr_encrypt as aes_ctr_decrypt;


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sm2_gen() {
        unsafe {
            let mut key = std::mem::MaybeUninit::uninit();
            let r = sm2_key_generate(key.as_mut_ptr());
            assert_eq!(r, 1);
            let key = key.assume_init();
            println!("SM2_KEY: {key:?}")
        }
    }
}

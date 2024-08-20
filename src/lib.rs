#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub use aes_ctr_encrypt as aes_ctr_decrypt;

#[macro_export]
macro_rules! asn1_boolean_to_der {
    ($ val:expr , $out:expr , $outlen:expr $(,)? ) => {
        asn1_boolean_to_der_ex(ASN1_TAG_ASN1_TAG_BOOLEAN, $val, $out, $outlen)
    };
}

#[macro_export]
macro_rules! asn1_boolean_from_der {
    ($ val:expr , $in:expr , $inlen:expr $(,)? ) => {
        asn1_boolean_from_der_ex(ASN1_TAG_ASN1_TAG_BOOLEAN, $val, $in, $inlen)
    };
}

#[macro_export]
macro_rules! asn1_int_to_der {
    ($ val:expr , $out:expr , $outlen:expr $(,)? ) => {
        asn1_int_to_der_ex(ASN1_TAG_ASN1_TAG_INTEGER, $val, $out, $outlen)
    };
}

#[macro_export]
macro_rules! asn1_int_from_der {
    ($ val:expr , $in:expr , $inlen:expr $(,)? ) => {
        asn1_int_from_der_ex(ASN1_TAG_ASN1_TAG_INTEGER, $val, $in, $inlen)
    };
}

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

pub const  SM2_MAX_PLAINTEXT_SIZE: usize = 255;
pub const SM2_MIN_PLAINTEXT_SIZE: usize = 1;

#[repr(C)]
#[derive(Debug)]
pub struct SM2_POINT {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

#[repr(C)]
#[derive(Debug)]
pub struct SM2_KEY {
    pub public_key: SM2_POINT,
    pub private_key: [u8; 32],
}

#[repr(C)]
#[derive(Debug)]
pub struct SM2_CIPHERTEXT {
    pub point: SM2_POINT,
    pub hash: [u8; 32usize],
    pub ciphertext_size: u8,
    pub ciphertext: [u8; SM2_MAX_PLAINTEXT_SIZE],
}

extern "C" {
    pub fn sm2_point_from_octets(p: *mut SM2_POINT, in_: *const u8, inlen: usize) -> isize;
    pub fn sm2_point_to_compressed_octets(p: *const SM2_POINT, out: *mut [u8; 33]);
    pub fn sm2_point_to_uncompressed_octets(p: *const SM2_POINT, out: *mut [u8; 65]);

    pub fn sm2_key_generate(key: *mut SM2_KEY) -> isize;
    pub fn sm2_key_set_private_key(key: *mut SM2_KEY, private_key: *const [u8; 32]) -> isize;
    pub fn sm2_key_set_public_key(key: *mut SM2_KEY, public_key: *const SM2_POINT) -> isize;
    pub fn sm2_do_encrypt(
        key: *const SM2_KEY,
        in_: *const u8,
        inlen: usize,
        out: *mut SM2_CIPHERTEXT,
    ) -> isize;
    pub fn sm2_do_decrypt(
        key: *const SM2_KEY,
        in_: *const SM2_CIPHERTEXT,
        out: *mut u8,
        outlen: *mut usize,
    ) -> isize;

}

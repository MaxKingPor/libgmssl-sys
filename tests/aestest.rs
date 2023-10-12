#![allow(unused)]

use hex::{FromHex, ToHex};
use libgmssl_sys::*;
use std::mem::{size_of, size_of_val};

#[test]
fn test_aes() {
    unsafe {
        let mut aes_key: AES_KEY = std::mem::zeroed();
        /* test 1 */

        let key128: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let rk128: [u32; 44] = [
            0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c, 0xa0fafe17, 0x88542cb1, 0x23a33939,
            0x2a6c7605, 0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f, 0x3d80477d, 0x4716fe3e,
            0x1e237e44, 0x6d7a883b, 0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00, 0xd4d1c6f8,
            0x7c839d87, 0xcaf2b8bc, 0x11f915bc, 0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,
            0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f, 0xead27321, 0xb58dbad2, 0x312bf560,
            0x7f8d292f, 0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e, 0xd014f9a8, 0xc9ee2589,
            0xe13f0cc8, 0xb6630ca6,
        ];
        /* test 2 */
        let key192: [u8; 24] = [
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90,
            0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
        ];
        let rk192: [u32; 4 * 13] = [
            0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, 0x62f8ead2, 0x522c6b7b, 0xfe0c91f7,
            0x2402f5a5, 0xec12068e, 0x6c827f6b, 0x0e7a95b9, 0x5c56fec2, 0x4db7b4bd, 0x69b54118,
            0x85a74796, 0xe92538fd, 0xe75fad44, 0xbb095386, 0x485af057, 0x21efb14f, 0xa448f6d9,
            0x4d6dce24, 0xaa326360, 0x113b30e6, 0xa25e7ed5, 0x83b1cf9a, 0x27f93943, 0x6a94f767,
            0xc0a69407, 0xd19da4e1, 0xec1786eb, 0x6fa64971, 0x485f7032, 0x22cb8755, 0xe26d1352,
            0x33f0b7b3, 0x40beeb28, 0x2f18a259, 0x6747d26b, 0x458c553e, 0xa7e1466c, 0x9411f1df,
            0x821f750a, 0xad07d753, 0xca400538, 0x8fcc5006, 0x282d166a, 0xbc3ce7b5, 0xe98ba06f,
            0x448c773c, 0x8ecc7204, 0x01002202,
        ];

        /* test 3 */
        let key256: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let rk256: [u32; 4 * 15] = [
            0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3,
            0x0914dff4, 0x9ba35411, 0x8e6925af, 0xa51a8b5f, 0x2067fcde, 0xa8b09c1a, 0x93d194cd,
            0xbe49846e, 0xb75d5b9a, 0xd59aecb8, 0x5bf3c917, 0xfee94248, 0xde8ebe96, 0xb5a9328a,
            0x2678a647, 0x98312229, 0x2f6c79b3, 0x812c81ad, 0xdadf48ba, 0x24360af2, 0xfab8b464,
            0x98c5bfc9, 0xbebd198e, 0x268c3ba7, 0x09e04214, 0x68007bac, 0xb2df3316, 0x96e939e4,
            0x6c518d80, 0xc814e204, 0x76a9fb8a, 0x5025c02d, 0x59c58239, 0xde136967, 0x6ccc5a71,
            0xfa256395, 0x9674ee15, 0x5886ca5d, 0x2e2f31d7, 0x7e0af1fa, 0x27cf73c3, 0x749c47ab,
            0x18501dda, 0xe2757e4f, 0x7401905a, 0xcafaaae3, 0xe4d59b34, 0x9adf6ace, 0xbd10190d,
            0xfe4890d1, 0xe6188d0b, 0x046df344, 0x706c631e,
        ];
        /* test 4 */
        let in1: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];
        let out1: [u8; 16] = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
            0x0b, 0x32,
        ];
        let mut buf = [0; 16];

        aes_set_encrypt_key(&mut aes_key, key128.as_ptr(), size_of_val(&key128));
        assert_eq!(aes_key.rk[..rk128.len()], rk128, "aes test 1 failed");

        aes_set_encrypt_key(&mut aes_key, key192.as_ptr(), size_of_val(&key192));
        assert_eq!(aes_key.rk[..rk192.len()], rk192, "aes test 2 failed");

        aes_set_encrypt_key(&mut aes_key, key256.as_ptr(), size_of_val(&key256));
        assert_eq!(aes_key.rk[..rk256.len()], rk256, "aes test 3 failed");

        aes_set_encrypt_key(&mut aes_key, key128.as_ptr(), size_of_val(&key128));
        aes_encrypt(&aes_key, in1.as_ptr(), buf.as_mut_ptr());
        assert_eq!(buf, out1, "aes test 4 failed");

        aes_set_decrypt_key(&mut aes_key, key128.as_ptr(), size_of_val(&key128));
        aes_decrypt(&aes_key, buf.as_ptr(), buf.as_mut_ptr());
        assert_eq!(buf, in1, "aes test 5 failed")
    }
}

#[test]
fn test_aes_ctr() {
    unsafe {
        // NIST SP 800-38A F.5.1
        let hex_key = "2b7e151628aed2a6abf7158809cf4f3c";
        let hex_ctr = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
        let hex_msg = concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710"
        );
        let hex_out = concat!(
            "874d6191b620e3261bef6864990db6ce",
            "9806f66b7970fdff8617187bb9fffdff",
            "5ae4df3edbd5d35e5b4f09020db03eab",
            "1e031dda2fbe03d1792170a0f3009cee"
        );

        let mut aes_key: AES_KEY = std::mem::zeroed();
        let mut key: [u8; 32] = [0; 32];
        let mut ctr: [u8; 16] = [0; 16];
        let mut msg: [u8; 64] = [0; 64];
        let mut out: [u8; 64] = [0; 64];
        let mut buf: [u8; 64] = [0; 64];
        let mut keylen = 0;
        let mut ctrlen = 0;
        let mut msglen = 0;
        let mut outlen = 0;
        let mut buflen = 0;
        hex_to_bytes(
            hex_key.as_ptr() as _,
            hex_key.len(),
            key.as_mut_ptr(),
            &mut keylen,
        );
        hex_to_bytes(
            hex_ctr.as_ptr() as _,
            hex_ctr.len(),
            ctr.as_mut_ptr(),
            &mut ctrlen,
        );
        hex_to_bytes(
            hex_msg.as_ptr() as _,
            hex_msg.len(),
            msg.as_mut_ptr(),
            &mut msglen,
        );
        hex_to_bytes(
            hex_out.as_ptr() as _,
            hex_out.len(),
            out.as_mut_ptr(),
            &mut outlen,
        );
        aes_set_encrypt_key(&mut aes_key, key.as_ptr(), keylen);
        aes_ctr_encrypt(
            &aes_key,
            ctr.as_mut_ptr(),
            msg.as_ptr(),
            msglen,
            buf.as_mut_ptr(),
        );
        buflen = msglen;
        assert_eq!(buf, out, "aes ctr test 1 failed");

        hex_to_bytes(
            hex_ctr.as_ptr() as _,
            hex_ctr.len(),
            ctr.as_mut_ptr(),
            &mut ctrlen,
        );
        aes_ctr_decrypt(
            &aes_key,
            ctr.as_mut_ptr(),
            buf.as_ptr(),
            buflen,
            buf.as_mut_ptr(),
        );
        assert_eq!(buf, msg, "aes ctr test 2 failed")
    }
}

#[allow(non_snake_case)]
struct AesGcmTests {
    K: &'static str,
    P: &'static str,
    A: &'static str,
    IV: &'static str,
    C: &'static str,
    T: &'static str,
}
#[allow(non_upper_case_globals)]
const aes_gcm_tests: [AesGcmTests; 7] = [
    // test 1
    AesGcmTests {
        K: "00000000000000000000000000000000",
        P: "",
        A: "",
        IV: "000000000000000000000000",
        C: "",
        T: "58e2fccefa7e3061367f1d57a4e7455a",
    },
    // test 2
    AesGcmTests {
        K: "00000000000000000000000000000000",
        P: "00000000000000000000000000000000",
        A: "",
        IV: "000000000000000000000000",
        C: "0388dace60b6a392f328c2b971b2fe78",
        T: "ab6e47d42cec13bdf53a67b21257bddf",
    },
    // test 3
    AesGcmTests {
        K: "feffe9928665731c6d6a8f9467308308",
        P: concat!(
            "d9313225f88406e5a55909c5aff5269a",
            "86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525",
            "b16aedf5aa0de657ba637b391aafd255"
        ),
        A: "",
        IV: "cafebabefacedbaddecaf888",
        C: concat!(
            "42831ec2217774244b7221b784d0d49c",
            "e3aa212f2c02a4e035c17e2329aca12e",
            "21d514b25466931c7d8f6a5aac84aa05",
            "1ba30b396a0aac973d58e091473f5985"
        ),
        T: "4d5c2af327cd64a62cf35abd2ba6fab4",
    },
    // test 4
    AesGcmTests {
        K: "feffe9928665731c6d6a8f9467308308",
        P: concat!(
            "d9313225f88406e5a55909c5aff5269a",
            "86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525",
            "b16aedf5aa0de657ba637b39"
        ),
        A: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        IV: "cafebabefacedbaddecaf888",
        C: concat!(
            "42831ec2217774244b7221b784d0d49c",
            "e3aa212f2c02a4e035c17e2329aca12e",
            "21d514b25466931c7d8f6a5aac84aa05",
            "1ba30b396a0aac973d58e091"
        ),
        T: "5bc94fbc3221a5db94fae95ae7121a47",
    },
    // test 5
    AesGcmTests {
        K: "feffe9928665731c6d6a8f9467308308",
        P: concat!(
            "d9313225f88406e5a55909c5aff5269a",
            "86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525",
            "b16aedf5aa0de657ba637b39"
        ),
        A: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        IV: "cafebabefacedbad",
        C: concat!(
            "61353b4c2806934a777ff51fa22a4755",
            "699b2a714fcdc6f83766e5f97b6c7423",
            "73806900e49f24b22b097544d4896b42",
            "4989b5e1ebac0f07c23f4598"
        ),
        T: "3612d2e79e3b0785561be14aaca2fccb",
    },
    // test 6
    AesGcmTests {
        K: "feffe9928665731c6d6a8f9467308308",
        P: concat!(
            "d9313225f88406e5a55909c5aff5269a",
            "86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525",
            "b16aedf5aa0de657ba637b39"
        ),
        A: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        IV: concat!(
            "9313225df88406e555909c5aff5269aa",
            "6a7a9538534f7da1e4c303d2a318a728",
            "c3c0c95156809539fcf0e2429a6b5254",
            "16aedbf5a0de6a57a637b39b"
        ),
        C: concat!(
            "8ce24998625615b603a033aca13fb894",
            "be9112a5c3a211a8ba262a3cca7e2ca7",
            "01e4a9a4fba43c90ccdcb281d48c7c6f",
            "d62875d2aca417034c34aee5"
        ),
        T: "619cc5aefffe0bfa462af43c1699d050",
    },
    // test 7
    AesGcmTests {
        K: "000000000000000000000000000000000000000000000000",
        P: "",
        A: "",
        IV: "000000000000000000000000",
        C: "",
        T: "cd33b28ac773f74ba00ed1f312572435",
    },
];
#[allow(non_snake_case)]
#[test]
fn test_aes_gcm() {
    unsafe {
        let mut err: isize = 0;
        let mut K = [0_u8; 32];
        let mut P = [0_u8; 64];
        let mut A = [0_u8; 32];
        let mut IV = [0_u8; 64];
        let mut C = [0_u8; 64];
        let mut T = [0_u8; 16];
        let mut Klen = 0;
        let mut Plen = 0;
        let mut Alen = 0;
        let mut IVlen = 0;
        let mut Clen = 0;
        let mut Tlen = 0;

        let mut aes_key: AES_KEY = std::mem::zeroed();
        let mut out = [0_u8; 64];
        let mut tag = [0_u8; 16];
        let mut buf = [0_u8; 64];
        let i = 0;
        for i in 0..aes_gcm_tests.len() {
            hex_to_bytes(
                aes_gcm_tests[i].K.as_ptr() as _,
                aes_gcm_tests[i].K.len(),
                K.as_mut_ptr(),
                &mut Klen,
            );
            hex_to_bytes(
                aes_gcm_tests[i].P.as_ptr() as _,
                aes_gcm_tests[i].P.len(),
                P.as_mut_ptr(),
                &mut Plen,
            );
            hex_to_bytes(
                aes_gcm_tests[i].A.as_ptr() as _,
                aes_gcm_tests[i].A.len(),
                A.as_mut_ptr(),
                &mut Alen,
            );
            hex_to_bytes(
                aes_gcm_tests[i].IV.as_ptr() as _,
                aes_gcm_tests[i].IV.len(),
                IV.as_mut_ptr(),
                &mut IVlen,
            );
            hex_to_bytes(
                aes_gcm_tests[i].C.as_ptr() as _,
                aes_gcm_tests[i].C.len(),
                C.as_mut_ptr(),
                &mut Clen,
            );
            hex_to_bytes(
                aes_gcm_tests[i].T.as_ptr() as _,
                aes_gcm_tests[i].T.len(),
                T.as_mut_ptr(),
                &mut Tlen,
            );

            aes_set_encrypt_key(&mut aes_key, K.as_ptr(), Klen);
            aes_gcm_encrypt(
                &aes_key,
                IV.as_ptr(),
                IVlen,
                A.as_ptr(),
                Alen,
                P.as_ptr(),
                Plen,
                out.as_mut_ptr(),
                Tlen,
                tag.as_mut_ptr(),
            );

            let result = aes_gcm_decrypt(
                &aes_key,
                IV.as_ptr(),
                IVlen,
                A.as_ptr(),
                Alen,
                out.as_ptr(),
                Plen,
                tag.as_ptr(),
                Tlen,
                buf.as_mut_ptr(),
            );
            assert_eq!(result, 1, "aes gcm test {} aes_gcm_decrypt error", i + 1);
            assert_eq!(buf, P, "aes gcm test {}", i + 1)
        }
    }
}


#![allow(unused)]

use hex::ToHex;
use libgmssl_sys::*;
use std::mem::{size_of, size_of_val};

#[test]
fn test_aead_sm4_cbc_sm3_hmac() {
    unsafe {
        let mut aead_ctx: SM4_CBC_SM3_HMAC_CTX = std::mem::zeroed();
        let mut key = [0_u8; 16 + 32];
        let mut iv = [0_u8; 16];
        let mut aad = [0_u8; 29];
        let mut plain = [0_u8; 71];
        let mut plainlen = size_of_val(&plain);
        let mut cipher = [0_u8; 256];
        let mut cipherlen: usize = 0;
        let mut buf = [0_u8; 256];
        let mut buflen = 0;

        let mut lens = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
        let mut in_ = plain.as_mut_ptr();
        let mut out = cipher.as_mut_ptr();
        let mut inlen = 0;
        let mut outlen = 0;
        let mut i: usize = 0;

        rand_bytes(key.as_mut_ptr(), size_of_val(&key));
        rand_bytes(iv.as_mut_ptr(), size_of_val(&iv));
        rand_bytes(aad.as_mut_ptr(), size_of_val(&aad));
        rand_bytes(plain.as_mut_ptr(), plainlen);

        let result = sm4_cbc_sm3_hmac_encrypt_init(
            &mut aead_ctx,
            key.as_ptr(),
            size_of_val(&key),
            iv.as_ptr(),
            size_of_val(&iv),
            aad.as_ptr(),
            size_of_val(&aad),
        );
        assert_eq!(result, 1, "sm4_cbc_sm3_hmac_encrypt_init error");
        i = 0;
        while plainlen != 0 {
            assert!(i < size_of_val(&lens) / size_of_val(&lens[0]));
            inlen = if plainlen < lens[i] {
                plainlen
            } else {
                lens[i]
            };

            let result =
                sm4_cbc_sm3_hmac_encrypt_update(&mut aead_ctx, in_, inlen, out, &mut outlen);
            assert_eq!(result, 1, "sm4_cbc_sm3_hmac_encrypt_update error");

            in_ = in_.wrapping_add(inlen);
            plainlen -= inlen;
            out = out.wrapping_add(outlen);
            cipherlen += outlen;

            i += 1;
        }

        let result = sm4_cbc_sm3_hmac_encrypt_finish(&mut aead_ctx, out, &mut outlen);
        assert_eq!(result, 1, "sm4_cbc_sm3_hmac_encrypt_finish error");

        out = out.wrapping_add(outlen);
        cipherlen += outlen;

        // format_bytes(stdout, 0, 4, "plaintext ", plain, sizeof(plain));
        // format_bytes(stdout, 0, 4, "ciphertext", cipher, cipherlen);
        println!("\tplaintext : {}", plain.encode_hex_upper::<String>());
        println!(
            "\tciphertext: {}",
            (&cipher[..cipherlen]).encode_hex_upper::<String>()
        );

        {
            let mut sm4_key: SM4_KEY = std::mem::zeroed();
            let mut sm3_hmac_ctx: SM3_HMAC_CTX = std::mem::zeroed();
            let mut tmp = [0_u8; 256];
            let mut tmplen: usize = 0;

            sm4_set_encrypt_key(&mut sm4_key, key.as_ptr());
            let result = sm4_cbc_padding_encrypt(
                &sm4_key,
                iv.as_ptr(),
                plain.as_ptr(),
                size_of_val(&plain),
                tmp.as_mut_ptr(),
                &mut tmplen,
            );
            assert_eq!(result, 1, "sm4_cbc_padding_encrypt error");
            sm3_hmac_init(&mut sm3_hmac_ctx, key.as_ptr().wrapping_add(16), 32);
            sm3_hmac_update(&mut sm3_hmac_ctx, aad.as_ptr(), size_of_val(&aad));
            sm3_hmac_update(&mut sm3_hmac_ctx, tmp.as_ptr(), tmplen);
            sm3_hmac_finish(&mut sm3_hmac_ctx, tmp.as_mut_ptr().wrapping_add(tmplen));
            tmplen += 32;
            // format_bytes(stdout, 0, 4, "ciphertext", tmp, tmplen);
            println!(
                "\tciphertext: {}",
                (&tmp[..tmplen]).encode_hex_upper::<String>()
            );

            assert_eq!(cipherlen, tmplen, "cipherlen != tmplen");
            assert_eq!(
                cipher[..tmplen],
                tmp[..tmplen],
                "cipher[..tmplen] != tmp[..tmplen]"
            )
        }

        in_ = cipher.as_mut_ptr();
        out = buf.as_mut_ptr();

        let result = sm4_cbc_sm3_hmac_decrypt_init(
            &mut aead_ctx,
            key.as_ptr(),
            size_of_val(&key),
            iv.as_ptr(),
            size_of_val(&iv),
            aad.as_ptr(),
            size_of_val(&aad),
        );
        assert_eq!(result, 1, "sm4_cbc_sm3_hmac_decrypt_init error");

        i = size_of_val(&lens) / size_of_val(&lens[0]) - 1;
        while cipherlen != 0 {
            inlen = if cipherlen < lens[i] {
                cipherlen
            } else {
                lens[i]
            };

            let restult =
                sm4_cbc_sm3_hmac_decrypt_update(&mut aead_ctx, in_, inlen, out, &mut outlen);
            assert_eq!(restult, 1, "sm4_cbc_sm3_hmac_decrypt_update error");

            in_ = in_.wrapping_add(inlen);
            cipherlen -= inlen;
            out = out.wrapping_add(outlen);
            buflen += outlen;

            i -= 1;
        }

        let result = sm4_cbc_sm3_hmac_decrypt_finish(&mut aead_ctx, out, &mut outlen);
        assert_eq!(result, 1, "sm4_cbc_sm3_hmac_decrypt_finish error");
        out = out.wrapping_add(outlen);
        buflen += outlen;
        // format_bytes(stdout, 0, 4, "plaintext ", buf, buflen);

        println!(
            "\tplaintext : {}",
            (&buf[..buflen]).encode_hex_upper::<String>()
        );
        assert_eq!(buflen, size_of_val(&plain), "buflen != size_of_val(&plain)");
        assert_eq!(
            buf[..size_of_val(&plain)],
            plain,
            "buf[..size_of_val(&plain)] != plain"
        )
    }
}

#[test]
fn test_aead_sm4_ctr_sm3_hmac() {
    unsafe {
        let mut aead_ctx: SM4_CTR_SM3_HMAC_CTX = std::mem::zeroed();
        let mut key = [0_u8; 16 + 32];
        let mut iv = [0_u8; 16];
        let mut aad = [0_u8; 29];
        let mut plain = [0_u8; 71];
        let mut plainlen = size_of_val(&plain);
        let mut cipher = [0_u8; 256];
        let mut cipherlen: usize = 0;
        let mut buf = [0_u8; 256];
        let mut buflen = 0;

        let mut lens = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
        let mut in_ = plain.as_mut_ptr();
        let mut out = cipher.as_mut_ptr();
        let mut inlen = 0;
        let mut outlen = 0;
        let mut i: usize = 0;

        rand_bytes(key.as_mut_ptr(), size_of_val(&key));
        rand_bytes(iv.as_mut_ptr(), size_of_val(&iv));
        rand_bytes(aad.as_mut_ptr(), size_of_val(&aad));
        rand_bytes(plain.as_mut_ptr(), plainlen);

        let result = sm4_ctr_sm3_hmac_encrypt_init(
            &mut aead_ctx,
            key.as_ptr(),
            size_of_val(&key),
            iv.as_ptr(),
            size_of_val(&iv),
            aad.as_ptr(),
            size_of_val(&aad),
        );
        assert_eq!(result, 1, "sm4_ctr_sm3_hmac_encrypt_init error");
        i = 0;
        while plainlen != 0 {
            assert!(i < size_of_val(&lens) / size_of_val(&lens[0]));
            inlen = if plainlen < lens[i] {
                plainlen
            } else {
                lens[i]
            };

            let result =
                sm4_ctr_sm3_hmac_encrypt_update(&mut aead_ctx, in_, inlen, out, &mut outlen);
            assert_eq!(result, 1, "sm4_ctr_sm3_hmac_encrypt_update error");

            in_ = in_.wrapping_add(inlen);
            plainlen -= inlen;
            out = out.wrapping_add(outlen);
            cipherlen += outlen;

            i += 1;
        }

        let result = sm4_ctr_sm3_hmac_encrypt_finish(&mut aead_ctx, out, &mut outlen);
        assert_eq!(result, 1, "sm4_ctr_sm3_hmac_encrypt_finish error");

        out = out.wrapping_add(outlen);
        cipherlen += outlen;

        // format_bytes(stdout, 0, 4, "plaintext ", plain, sizeof(plain));
        // format_bytes(stdout, 0, 4, "ciphertext", cipher, cipherlen);
        println!("\tplaintext : {}", plain.encode_hex_upper::<String>());
        println!(
            "\tciphertext: {}",
            (&cipher[..cipherlen]).encode_hex_upper::<String>()
        );

        {
            let mut sm4_key: SM4_KEY = std::mem::zeroed();
            let mut ctr = [0_u8; 16];
            let mut sm3_hmac_ctx: SM3_HMAC_CTX = std::mem::zeroed();
            let mut tmp = [0_u8; 256];
            let mut tmplen: usize = 0;

            sm4_set_encrypt_key(&mut sm4_key, key.as_ptr());
            ctr.clone_from_slice(&iv);

            sm4_ctr_encrypt(
                &mut sm4_key,
                ctr.as_mut_ptr(),
                plain.as_ptr(),
                size_of_val(&plain),
                tmp.as_mut_ptr(),
            );
            tmplen = size_of_val(&plain);

            sm3_hmac_init(&mut sm3_hmac_ctx, key.as_ptr().wrapping_add(16), 32);
            sm3_hmac_update(&mut sm3_hmac_ctx, aad.as_ptr(), size_of_val(&aad));
            sm3_hmac_update(&mut sm3_hmac_ctx, tmp.as_ptr(), tmplen);
            sm3_hmac_finish(&mut sm3_hmac_ctx, tmp.as_mut_ptr().wrapping_add(tmplen));
            tmplen += 32;
            // format_bytes(stdout, 0, 4, "ciphertext", tmp, tmplen);
            println!(
                "\tciphertext: {}",
                (&tmp[..tmplen]).encode_hex_upper::<String>()
            );

            assert_eq!(cipherlen, tmplen, "cipherlen != tmplen");
            assert_eq!(
                cipher[..tmplen],
                tmp[..tmplen],
                "cipher[..tmplen] != tmp[..tmplen]"
            )
        }

        in_ = cipher.as_mut_ptr();
        out = buf.as_mut_ptr();

        let result = sm4_ctr_sm3_hmac_decrypt_init(
            &mut aead_ctx,
            key.as_ptr(),
            size_of_val(&key),
            iv.as_ptr(),
            size_of_val(&iv),
            aad.as_ptr(),
            size_of_val(&aad),
        );
        assert_eq!(result, 1, "sm4_ctr_sm3_hmac_decrypt_init error");

        i = size_of_val(&lens) / size_of_val(&lens[0]) - 1;
        while cipherlen != 0 {
            inlen = if cipherlen < lens[i] {
                cipherlen
            } else {
                lens[i]
            };

            let restult =
                sm4_ctr_sm3_hmac_decrypt_update(&mut aead_ctx, in_, inlen, out, &mut outlen);
            assert_eq!(restult, 1, "sm4_ctr_sm3_hmac_decrypt_update error");

            in_ = in_.wrapping_add(inlen);
            cipherlen -= inlen;
            out = out.wrapping_add(outlen);
            buflen += outlen;

            i -= 1;
        }

        let result = sm4_ctr_sm3_hmac_decrypt_finish(&mut aead_ctx, out, &mut outlen);
        assert_eq!(result, 1, "sm4_ctr_sm3_hmac_decrypt_finish error");
        out = out.wrapping_add(outlen);
        buflen += outlen;
        // format_bytes(stdout, 0, 4, "plaintext ", buf, buflen);

        println!(
            "\tplaintext : {}",
            (&buf[..buflen]).encode_hex_upper::<String>()
        );
        assert_eq!(buflen, size_of_val(&plain), "buflen != size_of_val(&plain)");
        assert_eq!(
            buf[..size_of_val(&plain)],
            plain,
            "buf[..size_of_val(&plain)] != plain"
        )
    }
}

#[test]
fn test_aead_sm4_gcm() {
    unsafe {
        let mut aead_ctx: SM4_GCM_CTX = std::mem::zeroed();
        let mut key = [0_u8; 16];
        let mut iv = [0_u8; 16];
        let mut aad = [0_u8; 29];
        let mut plain = [0_u8; 71];
        let mut plainlen = size_of_val(&plain);
        let mut cipher = [0_u8; 256];
        let mut cipherlen: usize = 0;
        let mut buf = [0_u8; 256];
        let mut buflen = 0;

        let mut lens = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
        let mut in_ = plain.as_mut_ptr();
        let mut out = cipher.as_mut_ptr();
        let mut inlen = 0;
        let mut outlen = 0;
        let mut i: usize = 0;

        rand_bytes(key.as_mut_ptr(), size_of_val(&key));
        rand_bytes(iv.as_mut_ptr(), size_of_val(&iv));
        rand_bytes(aad.as_mut_ptr(), size_of_val(&aad));
        rand_bytes(plain.as_mut_ptr(), plainlen);

        let result = sm4_gcm_encrypt_init(
            &mut aead_ctx,
            key.as_ptr(),
            size_of_val(&key),
            iv.as_ptr(),
            size_of_val(&iv),
            aad.as_ptr(),
            size_of_val(&aad),
            GHASH_SIZE as _,
        );
        assert_eq!(result, 1, "sm4_gcm_encrypt_init error");
        i = 0;
        while plainlen != 0 {
            assert!(i < size_of_val(&lens) / size_of_val(&lens[0]));
            inlen = if plainlen < lens[i] {
                plainlen
            } else {
                lens[i]
            };

            let result = sm4_gcm_encrypt_update(&mut aead_ctx, in_, inlen, out, &mut outlen);
            assert_eq!(result, 1, "sm4_gcm_encrypt_update error");

            in_ = in_.wrapping_add(inlen);
            plainlen -= inlen;
            out = out.wrapping_add(outlen);
            cipherlen += outlen;

            i += 1;
        }

        let result = sm4_gcm_encrypt_finish(&mut aead_ctx, out, &mut outlen);
        assert_eq!(result, 1, "sm4_gcm_encrypt_finish error");

        out = out.wrapping_add(outlen);
        cipherlen += outlen;

        // format_bytes(stdout, 0, 4, "plaintext ", plain, sizeof(plain));
        // format_bytes(stdout, 0, 4, "ciphertext", cipher, cipherlen);
        println!("\tplaintext : {}", plain.encode_hex_upper::<String>());
        println!(
            "\tciphertext: {}",
            (&cipher[..cipherlen]).encode_hex_upper::<String>()
        );

        {
            let mut sm4_key: SM4_KEY = std::mem::zeroed();
            let mut tmp = [0_u8; 256];
            let mut tmplen: usize = 0;

            sm4_set_encrypt_key(&mut sm4_key, key.as_ptr());

            let result = sm4_gcm_encrypt(
                &mut sm4_key,
                iv.as_ptr(),
                size_of_val(&iv),
                aad.as_ptr(),
                size_of_val(&aad),
                plain.as_ptr(),
                size_of_val(&plain),
                tmp.as_mut_ptr(),
                GHASH_SIZE as _,
                tmp.as_mut_ptr().wrapping_add(size_of_val(&plain)),
            );
            assert_eq!(result, 1, "sm4_gcm_encrypt error");
            tmplen = size_of_val(&plain) + GHASH_SIZE as usize;

            // format_bytes(stdout, 0, 4, "ciphertext", tmp, tmplen);
            println!(
                "\tciphertext: {}",
                (&tmp[..tmplen]).encode_hex_upper::<String>()
            );

            assert_eq!(cipherlen, tmplen, "cipherlen != tmplen");
            assert_eq!(
                cipher[..tmplen],
                tmp[..tmplen],
                "cipher[..tmplen] != tmp[..tmplen]"
            )
        }

        in_ = cipher.as_mut_ptr();
        out = buf.as_mut_ptr();

        let result = sm4_gcm_decrypt_init(
            &mut aead_ctx,
            key.as_ptr(),
            size_of_val(&key),
            iv.as_ptr(),
            size_of_val(&iv),
            aad.as_ptr(),
            size_of_val(&aad),
            GHASH_SIZE as _,
        );
        assert_eq!(result, 1, "sm4_gcm_decrypt_init error");

        i = size_of_val(&lens) / size_of_val(&lens[0]) - 1;
        while cipherlen != 0 {
            inlen = if cipherlen < lens[i] {
                cipherlen
            } else {
                lens[i]
            };

            let restult = sm4_gcm_decrypt_update(&mut aead_ctx, in_, inlen, out, &mut outlen);
            assert_eq!(restult, 1, "sm4_gcm_decrypt_update error");

            in_ = in_.wrapping_add(inlen);
            cipherlen -= inlen;
            out = out.wrapping_add(outlen);
            buflen += outlen;

            i -= 1;
        }

        let result = sm4_gcm_decrypt_finish(&mut aead_ctx, out, &mut outlen);
        assert_eq!(result, 1, "sm4_gcm_decrypt_finish error");
        out = out.wrapping_add(outlen);
        buflen += outlen;
        // format_bytes(stdout, 0, 4, "plaintext ", buf, buflen);

        println!(
            "\tplaintext : {}",
            (&buf[..buflen]).encode_hex_upper::<String>()
        );
        assert_eq!(buflen, size_of_val(&plain), "buflen != size_of_val(&plain)");
        assert_eq!(
            buf[..size_of_val(&plain)],
            plain,
            "buf[..size_of_val(&plain)] != plain"
        )
    }
}

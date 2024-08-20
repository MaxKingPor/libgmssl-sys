# GMSSL rust 绑定

* 此仓库为[GmSSL](https://github.com/guanzhi/GmSSL)的绑定 采用静态链接

# Features
* `ENABLE_SM2_ARM64`    Enable SM2_Z256 ARMv8 assembly default `OFF`
* `ENABLE_SM3_ARM64`    Enable SM3 Arm Neon implementation (10% faster on Apple M2) default `OFF`
* `ENABLE_SM4_ARM64`    Enable SM4 AARCH64 assembly implementation default `OFF`
* `ENABLE_SM4_CE`   Enable SM4 ARM CE assembly implementation default `OFF`
* `ENABLE_SM9_ARM64`    Enable SM9_Z256 ARMv8 assembly default `OFF`
* `ENABLE_GMUL_ARM64`   Enable GF(2^128) Multiplication AArch64 assembly default `OFF`
* `ENABLE_SM4_AVX2` Enable SM4 AVX2 8x implementation default `OFF`
* `ENABLE_SM4_AESNI`    Enable SM4 AES-NI (4x) implementation default `OFF`
* `ENABLE_SM2_AMD64`    Enable SM2_Z256 X86_64 assembly default `OFF`
* `ENABLE_SM3_SSE`      Enable SM3 SSE assembly implementation default `OFF`
* `ENABLE_SM4_CTR_AESNI_AVX`    Enable SM4 CTR AESNI+AVX assembly implementation default `OFF`
* `ENABLE_SM4_CL`   Enable SM4 OpenCL default `OFF`
* `ENABLE_INTEL_RDRAND` Enable Intel RDRAND instructions default `OFF`
* `ENABLE_INTEL_RDSEED` Enable Intel RDSEED instructions default `OFF`
* `ENABLE_SM4_ECB`  Enable SM4 ECB mode default `ON`
* `ENABLE_SM4_OFB`  Enable SM4 OFB mode default `ON`
* `ENABLE_SM4_CFB`  Enable SM4 CFB mode default `ON`
* `ENABLE_SM4_CCM`  Enable SM4 CCM mode default `ON`
* `ENABLE_SM4_XTS`  Enable SM4 XTS mode default `ON`
* `ENABLE_SM4_CBC_MAC`  Enable SM4-CBC-MAC default `ON`
* `ENABLE_SM2_EXTS` Enable SM2 Extensions default `OFF`
* `ENABLE_SM3_XMSS` Enable SM3-XMSS signature default `ON`
* `ENABLE_SHA1` Enable SHA1 default `ON`
* `ENABLE_SHA2` Enable SHA2 default `ON`
* `ENABLE_AES`  Enable AES default `ON`
* `ENABLE_CHACHA20` Enable Chacha20 default `ON`
* `ENABLE_SKF`  Enable SKF module default `OFF`
* `ENABLE_SDF`  Enable SDF module default `ON`
* `ENABLE_ASM_UNDERSCORE_PREFIX`    Add prefix `_` to assembly symbols default `ON`
* `ENABLE_TLS_DEBUG`    Enable TLS and TLCP print debug message default `OFF`
* `ENABLE_SM2_ENC_PRE_COMPUTE`  Enable SM2 encryption precomputing default `ON`


* TODO: Disable som cmake default enabled
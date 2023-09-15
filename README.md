# GMSSL rust 绑定

* 此仓库为[GmSSL-3.1.0](https://github.com/guanzhi/GmSSL)的绑定 采用静态链接

# Features
* `ENABLE_SM2_ALGOR_ID_ENCODE_NULL` Enable AlgorithmIdenifier with algorithm sm2sign_with_sm3 encode a NULL object as parameters
* `ENABLE_SM2_PRIVATE_KEY_EXPORT` Enable export un-encrypted SM2 private key
* `ENABLE_TLS_DEBUG` Enable TLS and TLCP print debug message
* `ENABLE_SM3_AVX_BMI2` Enable SM3 AVX+BMI2 assembly implementation
* `ENABLE_SM4_AESNI_AVX` Enable SM4 AESNI+AVX assembly implementation
* `ENABLE_SM2_EXTS` Enable SM2 Extensions
* `ENABLE_BROKEN_CRYPTO`  Enable broken crypto algorithms
* `ENABLE_RDRND` Enable Intel RDRND instructions
* `ENABLE_GMT_0105_RNG` Enable GM/T 0105 Software RNG
* `ENABLE_HTTP_TESTS` Enable HTTP GET/POST related tests
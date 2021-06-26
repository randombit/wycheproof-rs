#[test]
fn test_aead_parsing() {
    let tests = [
        "aead_aes_siv_cmac",
        "aegis128L",
        "aegis128",
        "aegis256",
        "aes_ccm",
        "aes_eax",
        "aes_gcm_siv",
        "aes_gcm",
        "chacha20_poly1305",
        "xchacha20_poly1305",
    ];

    for test in tests {
        let _kats = wycheproof::AeadTestSet::load(test).unwrap();
    }
}

#[test]
fn print_gcm_tests() {
    use hex::encode as hex_encode;

    let test_set = wycheproof::AeadTestSet::load("aes_gcm").unwrap();

    for test_group in test_set.test_groups {
        println!(
            "* Group key size:{} tag size:{} nonce size:{}",
            test_group.key_size, test_group.tag_size, test_group.nonce_size,
        );
        for test in test_group.tests {
            println!(
                "Test:{} Key:{} AAD:{} PT:{} CT:{} Tag:{}",
                test.tc_id,
                hex_encode(test.key),
                hex_encode(test.aad),
                hex_encode(test.pt),
                hex_encode(test.ct),
                hex_encode(test.tag)
            );
        }
    }
}

#[test]
fn test_daead_parsing() {
    let tests = ["aes_siv_cmac"];

    for test in tests {
        let _kats = wycheproof::DaeadTestSet::load(test).unwrap();
    }
}

#[test]
fn test_kw_parsing() {
    let tests = ["kw", "kwp"];

    for test in tests {
        let _kats = wycheproof::KeywrapTestSet::load(test).unwrap();
    }
}

#[test]
fn test_ecdsa_verify_parsing() {
    let tests = [
        "ecdsa_brainpoolP224r1_sha224",
        "ecdsa_brainpoolP256r1_sha256",
        "ecdsa_brainpoolP320r1_sha384",
        "ecdsa_brainpoolP384r1_sha384",
        "ecdsa_brainpoolP512r1_sha512",
        "ecdsa_secp224r1_sha224",
        "ecdsa_secp224r1_sha256",
        "ecdsa_secp224r1_sha3_224",
        "ecdsa_secp224r1_sha3_256",
        "ecdsa_secp224r1_sha3_512",
        "ecdsa_secp224r1_sha512",
        "ecdsa_secp256k1_sha256",
        "ecdsa_secp256k1_sha3_256",
        "ecdsa_secp256k1_sha3_512",
        "ecdsa_secp256k1_sha512",
        "ecdsa_secp256r1_sha256",
        "ecdsa_secp256r1_sha3_256",
        "ecdsa_secp256r1_sha3_512",
        "ecdsa_secp256r1_sha512",
        "ecdsa_secp384r1_sha3_384",
        "ecdsa_secp384r1_sha3_512",
        "ecdsa_secp384r1_sha384",
        "ecdsa_secp384r1_sha512",
        "ecdsa_secp521r1_sha3_512",
        "ecdsa_secp521r1_sha512",
        "ecdsa",
        "ecdsa_brainpoolP224r1_sha224_p1363",
        "ecdsa_brainpoolP256r1_sha256_p1363",
        "ecdsa_brainpoolP320r1_sha384_p1363",
        "ecdsa_brainpoolP384r1_sha384_p1363",
        "ecdsa_brainpoolP512r1_sha512_p1363",
        "ecdsa_secp224r1_sha224_p1363",
        "ecdsa_secp224r1_sha256_p1363",
        "ecdsa_secp224r1_sha512_p1363",
        "ecdsa_secp256k1_sha256_p1363",
        "ecdsa_secp256k1_sha512_p1363",
        "ecdsa_secp256r1_sha256_p1363",
        "ecdsa_secp256r1_sha512_p1363",
        "ecdsa_secp384r1_sha384_p1363",
        "ecdsa_secp384r1_sha512_p1363",
        "ecdsa_secp521r1_sha512_p1363",
        "ecdsa_webcrypto",
    ];

    for test in tests {
        let _kats = wycheproof::EcdsaVerifyTestSet::load(test).unwrap();
    }
}

#[test]
fn test_rsa_pkcs1_verify_parsing() {
    let tests = [
        "rsa_signature_2048_sha224",
        "rsa_signature_2048_sha256",
        "rsa_signature_2048_sha3_224",
        "rsa_signature_2048_sha3_256",
        "rsa_signature_2048_sha3_384",
        "rsa_signature_2048_sha3_512",
        "rsa_signature_2048_sha384",
        "rsa_signature_2048_sha512_224",
        "rsa_signature_2048_sha512_256",
        "rsa_signature_2048_sha512",
        "rsa_signature_3072_sha256",
        "rsa_signature_3072_sha3_256",
        "rsa_signature_3072_sha3_384",
        "rsa_signature_3072_sha3_512",
        "rsa_signature_3072_sha384",
        "rsa_signature_3072_sha512_256",
        "rsa_signature_3072_sha512",
        "rsa_signature_4096_sha384",
        "rsa_signature_4096_sha512_256",
        "rsa_signature_4096_sha512",
        "rsa_signature",
    ];

    for test in tests {
        let _kats = wycheproof::RsaPkcs1VerifyTestSet::load(test).unwrap();
    }
}

#[test]
fn test_dsa_verify_parsing() {
    let tests = [
        "dsa_2048_224_sha224",
        "dsa_2048_224_sha256",
        "dsa_2048_256_sha256",
        "dsa_3072_256_sha256",
        "dsa",
    ];

    for test in tests {
        let _kats = wycheproof::DsaVerifyTestSet::load(test).unwrap();
    }
}

#[test]
fn test_hkdf_parsing() {
    let tests = ["hkdf_sha1", "hkdf_sha256", "hkdf_sha384", "hkdf_sha512"];

    for test in tests {
        let _kats = wycheproof::HkdfTestSet::load(test).unwrap();
    }
}

#[test]
fn test_rsa_pss_verify_parsing() {
    let tests = [
        "rsa_pss_2048_sha1_mgf1_20",
        "rsa_pss_2048_sha256_mgf1_0",
        "rsa_pss_2048_sha256_mgf1_32",
        "rsa_pss_2048_sha512_256_mgf1_28",
        "rsa_pss_2048_sha512_256_mgf1_32",
        "rsa_pss_3072_sha256_mgf1_32",
        "rsa_pss_4096_sha256_mgf1_32",
        "rsa_pss_4096_sha512_mgf1_32",
        "rsa_pss_misc",
    ];
    for test in tests {
        let _kats = wycheproof::RsaPssVerifyTestSet::load(test).unwrap();
    }
}

#[test]
fn test_oaep_decrypt_parsing() {
    let tests = [
        "rsa_oaep_2048_sha1_mgf1sha1",
        "rsa_oaep_2048_sha224_mgf1sha1",
        "rsa_oaep_2048_sha224_mgf1sha224",
        "rsa_oaep_2048_sha256_mgf1sha1",
        "rsa_oaep_2048_sha256_mgf1sha256",
        "rsa_oaep_2048_sha384_mgf1sha1",
        "rsa_oaep_2048_sha384_mgf1sha384",
        "rsa_oaep_2048_sha512_mgf1sha1",
        "rsa_oaep_2048_sha512_mgf1sha512",
        "rsa_oaep_3072_sha256_mgf1sha1",
        "rsa_oaep_3072_sha256_mgf1sha256",
        "rsa_oaep_3072_sha512_mgf1sha1",
        "rsa_oaep_3072_sha512_mgf1sha512",
        "rsa_oaep_4096_sha256_mgf1sha1",
        "rsa_oaep_4096_sha256_mgf1sha256",
        "rsa_oaep_4096_sha512_mgf1sha1",
        "rsa_oaep_4096_sha512_mgf1sha512",
        "rsa_oaep_misc",
    ];

    for test in tests {
        let _kats = wycheproof::RsaOaepDecryptTestSet::load(test).unwrap();
    }
}

#[test]
fn test_rsa_pkcs1_decrypt_parsing() {
    let tests = ["rsa_pkcs1_2048", "rsa_pkcs1_3072", "rsa_pkcs1_4096"];

    for test in tests {
        let _kats = wycheproof::RsaPkcs1DecryptTestSet::load(test).unwrap();
    }
}

#[test]
fn test_primality_parsing() {
    let _kats = wycheproof::PrimalityTestSet::load("primality").unwrap();
}

#[test]
fn test_ecdh_parsing() {
    let tests = [
        "ecdh_brainpoolP224r1",
        "ecdh_brainpoolP256r1",
        "ecdh_brainpoolP320r1",
        "ecdh_brainpoolP384r1",
        "ecdh_brainpoolP512r1",
        "ecdh_secp224r1_ecpoint",
        "ecdh_secp224r1",
        "ecdh_secp256k1",
        "ecdh_secp256r1_ecpoint",
        "ecdh_secp256r1",
        "ecdh_secp384r1_ecpoint",
        "ecdh_secp384r1",
        "ecdh_secp521r1_ecpoint",
        "ecdh_secp521r1",
        "ecdh",
    ];

    for test in tests {
        let _kats = wycheproof::EcdhTestSet::load(test).unwrap();
    }
}

#[test]
fn test_mac_parsing() {
    let tests = [
        "aes_cmac",
        "hmac_sha1",
        "hmac_sha224",
        "hmac_sha256",
        "hmac_sha3_224",
        "hmac_sha3_256",
        "hmac_sha3_384",
        "hmac_sha3_512",
        "hmac_sha384",
        "hmac_sha512",
        "vmac_64",
        "vmac_128",
        "gmac",
    ];
    for test in tests {
        let _kats = wycheproof::MacTestSet::load(test).unwrap();
    }
}

#[test]
fn test_eddsa_parsing() {
    let tests = ["eddsa", "ed448"];
    for test in tests {
        let _kats = wycheproof::EddsaVerifyTestSet::load(test).unwrap();
    }
}

#[test]
fn test_rsa_pkcs1_sign_parsing() {
    let tests = ["rsa_sig_gen_misc"];
    for test in tests {
        let _kats = wycheproof::RsaPkcs1SignTestSet::load(test).unwrap();
    }
}

#[test]
fn test_aes_cbc_parsing() {
    let tests = ["aes_cbc_pkcs5"];
    for test in tests {
        let _kats = wycheproof::CipherTestSet::load(test).unwrap();
    }
}

#[test]
fn test_xdh_parsing() {
    let tests = ["x25519", "x448"];
    for test in tests {
        let _kats = wycheproof::XdhTestSet::load(test).unwrap();
    }
}

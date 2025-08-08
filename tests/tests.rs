#[cfg(feature = "aead")]
#[test]
fn test_aead_parsing() -> Result<(), wycheproof::WycheproofError> {
    for test in wycheproof::aead::TestName::all() {
        let _kat = wycheproof::aead::TestSet::load(test)?;
    }
    Ok(())
}

#[cfg(feature = "cipher")]
#[test]
fn test_cipher_parsing() -> Result<(), wycheproof::WycheproofError> {
    for test in wycheproof::cipher::TestName::all() {
        let _kat = wycheproof::cipher::TestSet::load(test)?;
    }
    Ok(())
}

#[cfg(feature = "dsa")]
#[test]
fn test_dsa_parsing() -> Result<(), wycheproof::WycheproofError> {
    for test in wycheproof::dsa::TestName::all() {
        let _kat = wycheproof::dsa::TestSet::load(test)?;
    }
    Ok(())
}

#[cfg(feature = "ecdh")]
#[test]
fn test_ecdh_parsing() -> Result<(), wycheproof::WycheproofError> {
    for test in wycheproof::ecdh::TestName::all() {
        let _kat = wycheproof::ecdh::TestSet::load(test)?;
    }
    Ok(())
}

#[cfg(feature = "ecdsa")]
#[test]
fn test_ecdsa_parsing() -> Result<(), wycheproof::WycheproofError> {
    for test in wycheproof::ecdsa::TestName::all() {
        let _kat = wycheproof::ecdsa::TestSet::load(test)?;
    }
    Ok(())
}

#[cfg(feature = "eddsa")]
#[test]
fn test_eddsa_parsing() -> Result<(), wycheproof::WycheproofError> {
    for test in wycheproof::eddsa::TestName::all() {
        let _kat = wycheproof::eddsa::TestSet::load(test)?;
    }
    Ok(())
}

#[cfg(feature = "ec")]
#[test]
fn test_ec_curve_parsing() -> Result<(), wycheproof::WycheproofError> {
    for test in wycheproof::ec_curve::TestName::all() {
        let _kat = wycheproof::ec_curve::TestSet::load(test)?;
    }
    Ok(())
}

#[cfg(feature = "fpe")]
#[test]
fn test_fpe_str_parsing() -> Result<(), wycheproof::WycheproofError> {
    for test in wycheproof::fpe_str::TestName::all() {
        let _kat = wycheproof::fpe_str::TestSet::load(test)?;
    }
    Ok(())
}

#[cfg(feature = "fpe")]
#[test]
fn test_fpe_list_parsing() -> Result<(), wycheproof::WycheproofError> {
    for test in wycheproof::fpe_list::TestName::all() {
        let _kat = wycheproof::fpe_list::TestSet::load(test)?;
    }
    Ok(())
}

#[cfg(feature = "hkdf")]
#[test]
fn test_hkdf_parsing() -> Result<(), wycheproof::WycheproofError> {
    for test in wycheproof::hkdf::TestName::all() {
        let _kat = wycheproof::hkdf::TestSet::load(test)?;
    }
    Ok(())
}

#[cfg(feature = "keywrap")]
#[test]
fn test_keywrap_parsing() -> Result<(), wycheproof::WycheproofError> {
    for test in wycheproof::keywrap::TestName::all() {
        let _kat = wycheproof::keywrap::TestSet::load(test)?;
    }
    Ok(())
}

#[cfg(feature = "mac")]
#[test]
fn test_mac_parsing() -> Result<(), wycheproof::WycheproofError> {
    for test in wycheproof::mac::TestName::all() {
        let _kat = wycheproof::mac::TestSet::load(test)?;
    }
    Ok(())
}

#[cfg(feature = "mac")]
#[test]
fn test_mac_with_nonce_parsing() -> Result<(), wycheproof::WycheproofError> {
    for test in wycheproof::mac_with_nonce::TestName::all() {
        let _kat = wycheproof::mac_with_nonce::TestSet::load(test)?;
    }
    Ok(())
}

#[cfg(feature = "primality")]
#[test]
fn test_primality_parsing() -> Result<(), wycheproof::WycheproofError> {
    for test in wycheproof::primality::TestName::all() {
        let _kat = wycheproof::primality::TestSet::load(test)?;
    }
    Ok(())
}

#[cfg(feature = "rsa_enc")]
#[test]
fn test_rsa_oaep_parsing() -> Result<(), wycheproof::WycheproofError> {
    for test in wycheproof::rsa_oaep::TestName::all() {
        let _kat = wycheproof::rsa_oaep::TestSet::load(test)?;
    }
    Ok(())
}

#[cfg(feature = "rsa_enc")]
#[test]
fn test_rsa_pkcs1_decrypt_parsing() -> Result<(), wycheproof::WycheproofError> {
    for test in wycheproof::rsa_pkcs1_decrypt::TestName::all() {
        let _kat = wycheproof::rsa_pkcs1_decrypt::TestSet::load(test)?;
    }
    Ok(())
}

#[cfg(feature = "rsa_sig")]
#[test]
fn test_rsa_pkcs1_verify_parsing() -> Result<(), wycheproof::WycheproofError> {
    for test in wycheproof::rsa_pkcs1_verify::TestName::all() {
        let _kat = wycheproof::rsa_pkcs1_verify::TestSet::load(test)?;
    }
    Ok(())
}

#[cfg(feature = "rsa_sig")]
#[test]
fn test_rsa_pss_verify_parsing() -> Result<(), wycheproof::WycheproofError> {
    for test in wycheproof::rsa_pss_verify::TestName::all() {
        let _kat = wycheproof::rsa_pss_verify::TestSet::load(test)?;
    }
    Ok(())
}

#[cfg(feature = "xdh")]
#[test]
fn test_xdh_parsing() -> Result<(), wycheproof::WycheproofError> {
    for test in wycheproof::xdh::TestName::all() {
        let _kat = wycheproof::xdh::TestSet::load(test)?;
    }
    Ok(())
}

#[cfg(feature = "mldsa_sign")]
#[test]
fn test_mldsa_sign_parsing() -> Result<(), wycheproof::WycheproofError> {
    for test in wycheproof::mldsa_sign::TestName::all() {
        let _kat = wycheproof::mldsa_sign::TestSet::load(test)?;
    }
    Ok(())
}

#[cfg(feature = "mldsa_verify")]
#[test]
fn test_mldsa_verify_parsing() -> Result<(), wycheproof::WycheproofError> {
    for test in wycheproof::mldsa_verify::TestName::all() {
        let _kat = wycheproof::mldsa_verify::TestSet::load(test)?;
    }
    Ok(())
}

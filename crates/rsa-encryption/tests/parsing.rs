#[test]
fn parses_all_rsa_encryption_vectors() -> Result<(), wycheproof_ng_core::WycheproofError> {
    for test in wycheproof_ng_rsa_encryption::rsa_oaep::TestName::all() {
        let _kat = wycheproof_ng_rsa_encryption::rsa_oaep::TestSet::load(test)?;
    }

    for test in wycheproof_ng_rsa_encryption::rsa_pkcs1_decrypt::TestName::all() {
        let _kat = wycheproof_ng_rsa_encryption::rsa_pkcs1_decrypt::TestSet::load(test)?;
    }

    Ok(())
}

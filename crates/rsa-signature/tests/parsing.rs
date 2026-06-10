#[test]
fn parses_all_rsa_signature_vectors() -> Result<(), wycheproof_ng_core::WycheproofError> {
    for test in wycheproof_ng_rsa_signature::rsa_pkcs1_sig_gen::TestName::all() {
        let _kat = wycheproof_ng_rsa_signature::rsa_pkcs1_sig_gen::TestSet::load(test)?;
    }

    for test in wycheproof_ng_rsa_signature::rsa_pkcs1_verify::TestName::all() {
        let _kat = wycheproof_ng_rsa_signature::rsa_pkcs1_verify::TestSet::load(test)?;
    }

    for test in wycheproof_ng_rsa_signature::rsa_pss_verify::TestName::all() {
        let _kat = wycheproof_ng_rsa_signature::rsa_pss_verify::TestSet::load(test)?;
    }

    Ok(())
}

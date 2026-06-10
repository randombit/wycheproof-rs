#[test]
fn parses_all_mldsa_vectors() -> Result<(), wycheproof_ng_core::WycheproofError> {
    for test in wycheproof_ng_mldsa::mldsa_sign::TestName::all() {
        let _kat = wycheproof_ng_mldsa::mldsa_sign::TestSet::load(test)?;
    }

    for test in wycheproof_ng_mldsa::mldsa_verify::TestName::all() {
        let _kat = wycheproof_ng_mldsa::mldsa_verify::TestSet::load(test)?;
    }

    Ok(())
}

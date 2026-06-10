#[test]
fn parses_all_ecdsa_vectors() -> Result<(), wycheproof_ng_core::WycheproofError> {
    for test in wycheproof_ng_ecdsa::TestName::all() {
        let _kat = wycheproof_ng_ecdsa::TestSet::load(test)?;
    }

    Ok(())
}

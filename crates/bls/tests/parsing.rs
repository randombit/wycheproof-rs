#[test]
fn parses_all_bls_vectors() -> Result<(), wycheproof_ng_core::WycheproofError> {
    for test in wycheproof_ng_bls::TestName::all() {
        let _kat = wycheproof_ng_bls::TestSet::load(test)?;
    }

    Ok(())
}

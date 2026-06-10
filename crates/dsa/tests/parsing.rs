#[test]
fn parses_all_dsa_vectors() -> Result<(), wycheproof_ng_core::WycheproofError> {
    for test in wycheproof_ng_dsa::TestName::all() {
        let _kat = wycheproof_ng_dsa::TestSet::load(test)?;
    }

    Ok(())
}

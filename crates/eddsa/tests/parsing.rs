#[test]
fn parses_all_eddsa_vectors() -> Result<(), wycheproof_ng_core::WycheproofError> {
    for test in wycheproof_ng_eddsa::TestName::all() {
        let _kat = wycheproof_ng_eddsa::TestSet::load(test)?;
    }

    Ok(())
}

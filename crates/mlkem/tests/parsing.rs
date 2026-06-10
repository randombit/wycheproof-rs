#[test]
fn parses_all_mlkem_vectors() -> Result<(), wycheproof_ng_core::WycheproofError> {
    for test in wycheproof_ng_mlkem::TestName::all() {
        let _kat = wycheproof_ng_mlkem::TestSet::load(test)?;
    }

    Ok(())
}

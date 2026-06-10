#[test]
fn parses_all_aead_vectors() -> Result<(), wycheproof_ng_core::WycheproofError> {
    for test in wycheproof_ng_aead::aead::TestName::all() {
        let _kat = wycheproof_ng_aead::aead::TestSet::load(test)?;
    }

    for test in wycheproof_ng_aead::daead::TestName::all() {
        let _kat = wycheproof_ng_aead::daead::TestSet::load(test)?;
    }

    Ok(())
}

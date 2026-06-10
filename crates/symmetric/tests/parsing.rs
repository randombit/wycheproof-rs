#[test]
fn parses_all_symmetric_vectors() -> Result<(), wycheproof_ng_core::WycheproofError> {
    for test in wycheproof_ng_symmetric::cipher::TestName::all() {
        let _kat = wycheproof_ng_symmetric::cipher::TestSet::load(test)?;
    }

    for test in wycheproof_ng_symmetric::keywrap::TestName::all() {
        let _kat = wycheproof_ng_symmetric::keywrap::TestSet::load(test)?;
    }

    for test in wycheproof_ng_symmetric::mac::TestName::all() {
        let _kat = wycheproof_ng_symmetric::mac::TestSet::load(test)?;
    }

    for test in wycheproof_ng_symmetric::mac_with_nonce::TestName::all() {
        let _kat = wycheproof_ng_symmetric::mac_with_nonce::TestSet::load(test)?;
    }

    Ok(())
}

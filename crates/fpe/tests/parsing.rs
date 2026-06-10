#[test]
fn parses_all_fpe_vectors() -> Result<(), wycheproof_ng_core::WycheproofError> {
    for test in wycheproof_ng_fpe::fpe_list::TestName::all() {
        let _kat = wycheproof_ng_fpe::fpe_list::TestSet::load(test)?;
    }

    for test in wycheproof_ng_fpe::fpe_str::TestName::all() {
        let _kat = wycheproof_ng_fpe::fpe_str::TestSet::load(test)?;
    }

    Ok(())
}

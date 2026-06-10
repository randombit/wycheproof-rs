#[test]
fn parses_all_dh_vectors() -> Result<(), wycheproof_ng_core::WycheproofError> {
    for test in wycheproof_ng_dh::ec_curve::TestName::all() {
        let _kat = wycheproof_ng_dh::ec_curve::TestSet::load(test)?;
    }

    for test in wycheproof_ng_dh::ecdh::TestName::all() {
        let _kat = wycheproof_ng_dh::ecdh::TestSet::load(test)?;
    }

    for test in wycheproof_ng_dh::xdh::TestName::all() {
        let _kat = wycheproof_ng_dh::xdh::TestSet::load(test)?;
    }

    Ok(())
}

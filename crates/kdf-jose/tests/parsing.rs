#[test]
fn parses_all_kdf_jose_vectors() -> Result<(), wycheproof_ng_core::WycheproofError> {
    for test in wycheproof_ng_kdf_jose::hkdf::TestName::all() {
        let _kat = wycheproof_ng_kdf_jose::hkdf::TestSet::load(test)?;
    }

    for test in wycheproof_ng_kdf_jose::json_web::TestName::all() {
        let _kat = wycheproof_ng_kdf_jose::json_web::TestSet::load(test)?;
    }

    for test in wycheproof_ng_kdf_jose::pbes2::TestName::all() {
        let _kat = wycheproof_ng_kdf_jose::pbes2::TestSet::load(test)?;
    }

    for test in wycheproof_ng_kdf_jose::pbkdf2::TestName::all() {
        let _kat = wycheproof_ng_kdf_jose::pbkdf2::TestSet::load(test)?;
    }

    for test in wycheproof_ng_kdf_jose::primality::TestName::all() {
        let _kat = wycheproof_ng_kdf_jose::primality::TestSet::load(test)?;
    }

    Ok(())
}

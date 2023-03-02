use super::*;

fn int_from_base64<'de, D: Deserializer<'de>>(deserializer: D) -> Result<LargeInteger, D::Error> {
    let s: &str = Deserialize::deserialize(deserializer)?;
    let bytes = base64::decode_config(s, base64::URL_SAFE).map_err(D::Error::custom)?;
    Ok(LargeInteger::new(bytes))
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcdsaPublicJwk {
    #[serde(rename = "crv")]
    pub curve: EllipticCurve,
    pub kid: String,
    pub kty: String,
    #[serde(deserialize_with = "int_from_base64", rename = "x")]
    pub affine_x: LargeInteger,
    #[serde(deserialize_with = "int_from_base64", rename = "y")]
    pub affine_y: LargeInteger,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RsaPublicJwk {
    pub alg: String,
    #[serde(deserialize_with = "int_from_base64")]
    pub e: LargeInteger,
    pub kid: String,
    pub kty: String,
    #[serde(deserialize_with = "int_from_base64")]
    pub n: LargeInteger,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RsaPrivateJwk {
    pub alg: String,
    #[serde(deserialize_with = "int_from_base64")]
    pub d: LargeInteger,
    #[serde(deserialize_with = "int_from_base64")]
    pub dp: LargeInteger,
    #[serde(deserialize_with = "int_from_base64")]
    pub dq: LargeInteger,
    #[serde(deserialize_with = "int_from_base64")]
    pub e: LargeInteger,
    pub kid: String,
    pub kty: String,
    #[serde(deserialize_with = "int_from_base64")]
    pub n: LargeInteger,
    #[serde(deserialize_with = "int_from_base64")]
    pub p: LargeInteger,
    #[serde(deserialize_with = "int_from_base64")]
    pub q: LargeInteger,
    #[serde(deserialize_with = "int_from_base64")]
    pub qi: LargeInteger,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EddsaPublicJwk {
    #[serde(rename = "crv")]
    pub curve: EdwardsCurve,
    pub kid: String,
    pub kty: String,
    #[serde(deserialize_with = "int_from_base64")]
    pub x: LargeInteger,
}

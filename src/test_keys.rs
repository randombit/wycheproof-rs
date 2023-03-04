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

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RsaPrivate {
    #[serde(rename = "publicExponent")]
    e: LargeInteger,
    #[serde(rename = "privateExponent")]
    d: LargeInteger,
    #[serde(rename = "modulus")]
    n: LargeInteger,
    #[serde(rename = "prime1")]
    p: LargeInteger,
    #[serde(rename = "prime2")]
    q: LargeInteger,
    #[serde(rename = "exponent1")]
    d1: LargeInteger,
    #[serde(rename = "exponent2")]
    d2: LargeInteger,
    #[serde(rename = "coefficient")]
    c: LargeInteger,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RsaPublic {
    #[serde(rename = "publicExponent")]
    e: LargeInteger,
    #[serde(rename = "modulus")]
    n: LargeInteger,
}

define_typeid!(EcPublicKeyTypeId => "EcPublicKey");

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcdsaPublic {
    pub curve: EllipticCurve,
    #[serde(rename = "keySize")]
    pub key_size: usize,
    #[serde(rename = "type")]
    typ: EcPublicKeyTypeId,
    #[serde(rename = "uncompressed")]
    pub key: ByteString,
    #[serde(rename = "wx")]
    pub affine_x: LargeInteger,
    #[serde(rename = "wy")]
    pub affine_y: LargeInteger,
}

define_typeid!(DsaPublicKeyTypeId => "DsaPublicKey");

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsaPublic {
    pub g: LargeInteger,
    #[serde(rename = "keySize")]
    pub key_size: usize,
    pub p: LargeInteger,
    pub q: LargeInteger,
    #[serde(rename = "type")]
    typ: DsaPublicKeyTypeId,
    pub y: LargeInteger,
}

define_typeid!(EddsaPublicKeyTypeId => "EDDSAPublicKey");

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EddsaPublic {
    pub curve: EdwardsCurve,
    #[serde(rename = "keySize")]
    pub key_size: usize,
    pub pk: ByteString,
    #[serde(rename = "type")]
    typ: EddsaPublicKeyTypeId,
}

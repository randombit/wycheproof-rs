use super::*;

#[allow(dead_code)]
fn int_from_base64<'de, D: Deserializer<'de>>(deserializer: D) -> Result<LargeInteger, D::Error> {
    let s: &str = Deserialize::deserialize(deserializer)?;
    let bytes = data_encoding::BASE64URL_NOPAD
        .decode(s.as_bytes())
        .map_err(D::Error::custom)?;
    Ok(LargeInteger::new(bytes))
}

#[cfg(feature = "ecdsa")]
#[derive(Debug, Clone, Hash, Eq, PartialEq, serde_derive::Deserialize)]
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

#[cfg(feature = "rsa_sig")]
#[derive(Debug, Clone, Hash, Eq, PartialEq, serde_derive::Deserialize)]
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

#[cfg(feature = "rsa_enc")]
#[derive(Debug, Clone, Hash, Eq, PartialEq, serde_derive::Deserialize)]
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

#[cfg(feature = "eddsa")]
#[derive(Debug, Clone, Hash, Eq, PartialEq, serde_derive::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EddsaPublicJwk {
    #[serde(rename = "crv")]
    pub curve: EdwardsCurve,
    pub kid: String,
    pub kty: String,
    #[serde(deserialize_with = "int_from_base64")]
    pub x: LargeInteger,
}

#[cfg(feature = "rsa_enc")]
#[derive(Debug, Clone, Hash, Eq, PartialEq, serde_derive::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RsaPrivate {
    #[serde(rename = "publicExponent")]
    pub e: LargeInteger,
    #[serde(rename = "privateExponent")]
    pub d: LargeInteger,
    #[serde(rename = "modulus")]
    pub n: LargeInteger,
    #[serde(rename = "prime1")]
    pub p: LargeInteger,
    #[serde(rename = "prime2")]
    pub q: LargeInteger,
    #[serde(rename = "exponent1")]
    pub d1: LargeInteger,
    #[serde(rename = "exponent2")]
    pub d2: LargeInteger,
    #[serde(rename = "coefficient")]
    pub c: LargeInteger,
}

#[cfg(feature = "rsa_sig")]
#[derive(Debug, Clone, Hash, Eq, PartialEq, serde_derive::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RsaPublic {
    #[serde(rename = "publicExponent")]
    pub e: LargeInteger,
    #[serde(rename = "modulus")]
    pub n: LargeInteger,
}

define_typeid!(EcPublicKeyTypeId => "EcPublicKey");

#[cfg(feature = "ecdsa")]
#[derive(Debug, Clone, Hash, Eq, PartialEq, serde_derive::Deserialize)]
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

#[cfg(feature = "dsa")]
#[derive(Debug, Clone, Hash, Eq, PartialEq, serde_derive::Deserialize)]
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

#[cfg(feature = "eddsa")]
#[derive(Debug, Clone, Hash, Eq, PartialEq, serde_derive::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EddsaPublic {
    pub curve: EdwardsCurve,
    #[serde(rename = "keySize")]
    pub key_size: usize,
    pub pk: ByteString,
    #[serde(rename = "type")]
    typ: EddsaPublicKeyTypeId,
}

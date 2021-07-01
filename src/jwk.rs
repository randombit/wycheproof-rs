use super::*;

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcdsaPublicJwk {
    #[serde(rename = "crv")]
    pub curve: EllipticCurve,
    pub kid: String,
    pub kty: String,
    #[serde(deserialize_with = "vec_from_base64", rename = "x")]
    pub affine_x: Vec<u8>,
    #[serde(deserialize_with = "vec_from_base64", rename = "y")]
    pub affine_y: Vec<u8>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RsaPublicJwk {
    pub alg: String,
    #[serde(deserialize_with = "vec_from_base64")]
    pub e: Vec<u8>,
    pub kid: String,
    pub kty: String,
    #[serde(deserialize_with = "vec_from_base64")]
    pub n: Vec<u8>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RsaPrivateJwk {
    pub alg: String,
    #[serde(deserialize_with = "vec_from_base64")]
    pub d: Vec<u8>,
    #[serde(deserialize_with = "vec_from_base64")]
    pub dp: Vec<u8>,
    #[serde(deserialize_with = "vec_from_base64")]
    pub dq: Vec<u8>,
    #[serde(deserialize_with = "vec_from_base64")]
    pub e: Vec<u8>,
    pub kid: String,
    pub kty: String,
    #[serde(deserialize_with = "vec_from_base64")]
    pub n: Vec<u8>,
    #[serde(deserialize_with = "vec_from_base64")]
    pub p: Vec<u8>,
    #[serde(deserialize_with = "vec_from_base64")]
    pub q: Vec<u8>,
    #[serde(deserialize_with = "vec_from_base64")]
    pub qi: Vec<u8>,
}


pub fn hash(origin: &str) -> [u8;32] {
    use sha2::Digest;
    sha2::Sha256::digest(origin).into()
}
pub fn nonce(origin: &str) -> [u8;12] {
    use sha2::Digest;
    let hash: [u8;32] = sha2::Sha256::digest(origin).into();
    hash[0..12].try_into().unwrap()
}
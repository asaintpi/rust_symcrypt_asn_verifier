#![allow(warnings)]
// rsa.rs
use symcrypt::rsa::{RsaKey, RsaKeyUsage};
use symcrypt::hash::HashAlgorithm;
use symcrypt::errors::SymCryptError;

/// Determines the appropriate salt length for RSA-PSS signature verification based on the hash algorithm
///
/// Returns the salt length corresponding to the output size of the hash algorithm.
/// # Parameters:
/// * `hash_algorithm`: A reference to a [`HashAlgorithm`] indicating which hashing algorithm is being used
///
/// # Returns:
/// A `Result<usize, SymCryptError>` that:
/// - Returns `Ok(usize)` with the length of the salt in bytes if the hash algorithm is supported
/// - Returns `Err(SymCryptError)` with `SymCryptError::InvalidArgument` if the hash algorithm is not supported
///
/// # Supported Hash Algorithms:
/// - `Sha256`: Returns a salt length of 32 bytes
/// - `Sha384`: Returns a salt length of 48 bytes
/// - `Sha512`: Returns a salt length of 64 bytes
pub fn determine_salt_length(hash_algorithm: &HashAlgorithm) -> Result<usize, SymCryptError> {
    match hash_algorithm {
        HashAlgorithm::Sha256 => Ok(32),
        HashAlgorithm::Sha384 => Ok(48),
        HashAlgorithm::Sha512 => Ok(64),
        _ => Err(SymCryptError::InvalidArgument),
    }
}

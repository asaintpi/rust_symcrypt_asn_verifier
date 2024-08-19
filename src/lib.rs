#![allow(non_camel_case_types)]

// External crate imports
use symcrypt::ecc::{EcKey, EcKeyUsage, CurveType};
use symcrypt::errors::SymCryptError;
pub use symcrypt::hash::{HashAlgorithm, sha256, sha384, sha512, SHA256_RESULT_SIZE, SHA384_RESULT_SIZE, SHA512_RESULT_SIZE};
pub use symcrypt::rsa::{RsaKey, RsaKeyUsage};
use x509_parser::prelude::X509Certificate;

// Local crate imports
use crate::x509::SignatureScheme;
pub use crate::x509::{parse_x509_certificate, parse_x509_certificate_ec};

// Module declarations
pub mod rsa;
pub mod utils;
pub mod x509;

/// `parse_certificate` attempts to parse and verify a certificate's signature using either an RSA or EC key
///
/// This function provides an interface to handle certificate parsing for different cryptographic schemes
///
/// # Parameters:
/// * `data`: A slice of bytes (`&[u8]`) containing the certificate data
/// * `message`: A slice of bytes (`&[u8]`) representing the message that was signed
/// * `signature`: A `Vec<u8>` holding the signature of the message
/// * `signature_scheme`: The [`SignatureScheme`] enum detailing the algorithm used for signing
/// * `rsa_key`: An `Option<RsaKey>` which, if provided, will be used for RSA signature verification
/// * `ec_key`: An `Option<EcKey>` which, if provided, will be used for EC signature verification
///
/// # Returns:
/// A `Result<(), SymCryptError>` which is `Ok(())` if the certificate is successfully parsed and verified, or an `Err(SymCryptError)` if there is an error during parsing or if no valid key is provided
///
/// # Errors:
/// Returns `Err(SymCryptError::InvalidArgument)` if both `rsa_key` and `ec_key` are `None`, or if an error occurs during the parsing and verification process
pub fn parse_certificate(
    data: &[u8],
    message: &[u8],
    signature: Vec<u8>,
    signature_scheme: SignatureScheme,
    rsa_key: Option<RsaKey>,
    ec_key: Option<EcKey>) -> Result<(), SymCryptError> {

        if rsa_key.is_none() && ec_key.is_none() {
            return Err(SymCryptError::InvalidArgument);
        }
        match (rsa_key, ec_key) {
            (Some(rsa), _) => {
                parse_x509_certificate(data, message, signature, signature_scheme, rsa)
                    .map_err(|_| SymCryptError::InvalidArgument)
            },
            (_, Some(ec)) => {
                parse_x509_certificate_ec(data, message, signature, signature_scheme, ec)
                    .map_err(|_| SymCryptError::InvalidArgument)
            },
            _ => Err(SymCryptError::InvalidArgument),
        }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_parse_certificate() {
        let path = r"C:\temp\microsoft.der";
        let key_pair = RsaKey::generate_key_pair(2048, None, RsaKeyUsage::SignAndEncrypt).unwrap();
        let message = b"Testing Sha384 hash";
        let hashed_message_384 = sha384(message);
        let hash_algorithm = HashAlgorithm::Sha384;
        let signature = key_pair.pkcs1_sign(&hashed_message_384, hash_algorithm).unwrap();
        let public_key_blob = key_pair.export_public_key_blob().unwrap();

        let rsa_key = RsaKey::set_public_key(
            &public_key_blob.modulus,
            &public_key_blob.pub_exp,
            RsaKeyUsage::SignAndEncrypt,
        )
        .unwrap();
        
        let signature_scheme = SignatureScheme::RSA_PKCS1_SHA384;
        let data = fs::read(path).expect("Failed to read test certificate file");
        assert!(parse_certificate(&data, message, signature, signature_scheme, Some(rsa_key), None).is_ok());
    }

    #[test]
    fn test_parse_certificate_ec() {
        let path = r"C:\temp\google.der";
        let key = EcKey::generate_key_pair(CurveType::NistP256, EcKeyUsage::EcDsa).unwrap();
        let message = b"Testing Sha256 hash";
        let hashed_message_256 = sha256(message);
        let hash_algorithm = HashAlgorithm::Sha256;

        let signature = key.ecdsa_sign(&hashed_message_256).unwrap();
        let data = fs::read(path).expect("Failed to read test certificate file");
        let signature_scheme = SignatureScheme::ECDSA_NISTP256_SHA256;
        assert!(parse_certificate(&data, message, signature, signature_scheme, None, Some(key)).is_ok());
    }
}

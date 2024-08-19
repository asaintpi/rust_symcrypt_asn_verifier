// External crate imports
use der::{asn1::{Uint, ObjectIdentifier}, Decode, Reader};
use symcrypt::{
    ecc::{EcKey, EcKeyUsage, CurveType},
    errors::SymCryptError,
    hash::{HashAlgorithm, sha256, sha384, sha512, SHA256_RESULT_SIZE, SHA384_RESULT_SIZE, SHA512_RESULT_SIZE},
    rsa::{RsaKey},
};
use x509_parser::prelude::*;

// Local crate imports
use crate::rsa::*;
use crate::utils::*;

/// Represents the different signature schemes supported
///
/// Variants:
/// - `RSA_PKCS1_SHA256`: RSA with PKCS#1 padding using SHA-256
/// - `RSA_PKCS1_SHA384`: RSA with PKCS#1 padding using SHA-384
/// - `RSA_PKCS1_SHA512`: RSA with PKCS#1 padding using SHA-512
/// - `RSA_PSS_SHA256`: RSA with PSS padding using SHA-256
/// - `RSA_PSS_SHA384`: RSA with PSS padding using SHA-384
/// - `RSA_PSS_SHA512`: RSA with PSS padding using SHA-512
/// - `ECDSA_NISTP256_SHA256`: ECDSA with NISTP-256 curve and SHA-256
/// - `ECDSA_NISTP384_SHA384`: ECDSA with NISTP-384 curve and SHA-384
///
#[derive(Debug)]
pub enum SignatureScheme {
    RSA_PKCS1_SHA256,
    RSA_PKCS1_SHA384,
    RSA_PKCS1_SHA512,
    RSA_PSS_SHA256,
    RSA_PSS_SHA384,
    RSA_PSS_SHA512,
    ECDSA_NISTP256_SHA256,
    ECDSA_NISTP384_SHA384,
}

/// Parses an X.509 certificate for EC signature verification
///
/// This function extracts the certificate's public key information and verifies the signature using the provided EC key.
///
/// # Parameters:
/// * `data`: A slice of bytes (`&[u8]`) containing the DER-encoded X.509 certificate
/// * `message`: A slice of bytes (`&[u8]`) representing the message that was signed
/// * `signature`: A `Vec<u8>` containing the signature to be verified
/// * `signature_scheme`: The signature scheme used for signing, specified by [`SignatureScheme`]
/// * `ec_key`: The EC key to be used for signature verification
///
/// # Returns:
/// A `Result<(), SymCryptError>` indicating success or error during the parsing or signature verification process
pub fn parse_x509_certificate_ec(data: &[u8], message: &[u8], signature: Vec<u8>, signature_scheme: SignatureScheme, ec_key: EcKey) -> Result<(), SymCryptError> {
    let Ok((_, cert)) = X509Certificate::from_der(data) else {
        return Err(SymCryptError::InvalidBlob);
    };
    
    let spki = &cert.tbs_certificate.subject_pki;
    let algorithm_oid = spki.algorithm.algorithm.to_string();
    let ecc_oid = ObjectIdentifier::new("1.2.840.10045.2.1").unwrap().to_string();

    let hash_algorithm = match signature_scheme {
        SignatureScheme::ECDSA_NISTP256_SHA256 | SignatureScheme::RSA_PSS_SHA256 | SignatureScheme::RSA_PKCS1_SHA256 => HashAlgorithm::Sha256,
        SignatureScheme::ECDSA_NISTP384_SHA384 | SignatureScheme::RSA_PSS_SHA384 | SignatureScheme::RSA_PKCS1_SHA384 => HashAlgorithm::Sha384,
        SignatureScheme::RSA_PKCS1_SHA512 | SignatureScheme::RSA_PSS_SHA512 => HashAlgorithm::Sha512,
        _ => return Err(SymCryptError::IncompatibleFormat),
    };

    if algorithm_oid != ecc_oid {
        return Err(SymCryptError::WrongKeySize);
    } else if algorithm_oid == ecc_oid {
        let curve_type = match signature_scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => CurveType::NistP256,
            SignatureScheme::ECDSA_NISTP384_SHA384 => CurveType::NistP384,
            _ => return Err(SymCryptError::IncompatibleFormat),
        };
        let _ = handle_ecc(signature, curve_type, hash_algorithm, ec_key, message);
    } else {
        println!("Unknown certificate type.");
    }

    Ok(())
}

/// Parses an X.509 certificate for RSA signature verification
///
/// This function extracts the certificates public key information and verifies the signature using the provided RSA key
///
/// # Parameters:
/// * `data`: A slice of bytes (`&[u8]`) containing the DER-encoded X.509 certificate
/// * `message`: A slice of bytes (`&[u8]`) representing the message that was signed
/// * `signature`: A `Vec<u8>` containing the signature to be verified
/// * `signature_scheme`: The signature scheme used for signing, specified by [`SignatureScheme`]
/// * `rsa_key`: The RSA key to be used for signature verification
///
/// # Returns:
/// A `Result<(), SymCryptError>` indicating success or error during the parsing or signature verification process.
pub fn parse_x509_certificate(
    data: &[u8],
    message: &[u8],
    signature: Vec<u8>,
    signature_scheme: SignatureScheme,
    rsa_key: RsaKey
) -> Result<(), SymCryptError> {
    let (_, cert) = X509Certificate::from_der(data).map_err(|_| SymCryptError::InvalidBlob)?;
    
    let spki = &cert.tbs_certificate.subject_pki;
    let algorithm_oid = spki.algorithm.algorithm.to_string();

    let rsa_pkcs1_oid = ObjectIdentifier::new("1.2.840.113549.1.1.1").unwrap().to_string();
    let rsa_pss_oid = ObjectIdentifier::new("1.2.840.113549.1.1.10").unwrap().to_string();
    let ecc_oid = ObjectIdentifier::new("1.2.840.10045.2.1").unwrap().to_string();

    let hash_algorithm = match signature_scheme {
        SignatureScheme::RSA_PKCS1_SHA256 | SignatureScheme::RSA_PSS_SHA256 | SignatureScheme::ECDSA_NISTP256_SHA256 => HashAlgorithm::Sha256,
        SignatureScheme::RSA_PKCS1_SHA384 | SignatureScheme::RSA_PSS_SHA384 | SignatureScheme::ECDSA_NISTP384_SHA384 => HashAlgorithm::Sha384,
        SignatureScheme::RSA_PKCS1_SHA512 | SignatureScheme::RSA_PSS_SHA512 => HashAlgorithm::Sha512,
        _ => return Err(SymCryptError::IncompatibleFormat),
    };

    if algorithm_oid == rsa_pkcs1_oid {
        let _ = handle_rsa(signature, hash_algorithm, message, rsa_key);
    } else if algorithm_oid == rsa_pss_oid {
        let _ = handle_rsa_pss(signature, hash_algorithm, message, rsa_key);
    } else if algorithm_oid == ecc_oid {
        return Err(SymCryptError::WrongKeySize);
    } else {
        return Err(SymCryptError::InvalidArgument);
    }

    Ok(())
}

/// Handles the RSA signature verification process
///
/// This function uses the provided RSA key to verify a signature against a message. It supports
/// SHA-256, SHA-384, SHA-512 which are specified by the `hash_algorithm` passed in
///
/// # Parameters:
/// * `signature`: A `Vec<u8>` containing the signature to be verified
/// * `hash_algorithm`: Specifies the hash algorithm used for message hashing, from [`HashAlgorithm`]
/// * `message`: A slice of bytes (`&[u8]`) representing the original message that was signed
/// * `rsa_key`: An instance of `RsaKey` used for the verification process
///
/// # Returns:
/// A `Result<(), SymCryptError>` that indicates the success or failure of the signature verification
/// Returns `Ok(())` if the signature is verified successfully, and an `Err(SymCryptError)` for any errors during verification
fn handle_rsa(signature: Vec<u8>, hash_algorithm: HashAlgorithm, message: &[u8], rsa_key: RsaKey) -> Result<(), SymCryptError> {
    let verify_result = match hash_algorithm {
        HashAlgorithm::Sha256 => {
            let hashed_message_256 = sha256(message);
            rsa_key.pkcs1_verify(&hashed_message_256, &signature, hash_algorithm)
        },
        HashAlgorithm::Sha384 => {
            let hashed_message_384 = sha384(message);
            rsa_key.pkcs1_verify(&hashed_message_384, &signature, hash_algorithm)
        },
        HashAlgorithm::Sha512 => {
            let hashed_message_512 = sha512(message);
            rsa_key.pkcs1_verify(&hashed_message_512, &signature, hash_algorithm)
        },
        _ => {
            println!("Unsupported RSA PKCS1 hash algorithm");
            return Err(SymCryptError::InvalidArgument);
        }
    };

    verify_result.map_err(|e| {
        println!("Verification failed with error: {:?}", e);
        e
    }).map(|_| {
        println!("Verification successful.");
    })
}

/// Handles the RSA-PSS signature verification process
///
/// This function uses the provided RSA key to verify a PSS signature against a message with a specific hash algorithm
/// calculates the salt length, hashes the message, and performs the verification
///
/// # Parameters:
/// * `signature`: A `Vec<u8>` containing the signature to be verified
/// * `hash_algorithm`: Specifies the hash algorithm used for message hashing, from [`HashAlgorithm`]
/// * `message`: A slice of bytes (`&[u8]`) representing the original message that was signed
/// * `rsa_key`: An instance of `RsaKey` used for the verification process
///
/// # Returns:
/// A `Result<(), SymCryptError>` that indicates the success or failure of the signature verification
/// Returns `Ok(())` if the signature is verified successfully, and an `Err(SymCryptError)` for any errors encountered during verification
fn handle_rsa_pss(signature: Vec<u8>, hash_algorithm: HashAlgorithm, message: &[u8], rsa_key: RsaKey) -> Result<(), SymCryptError> {
    let verify_result = match hash_algorithm {
        HashAlgorithm::Sha256 | HashAlgorithm::Sha384 | HashAlgorithm::Sha512 => {
            let hashed_message = match hash_algorithm {
                HashAlgorithm::Sha256 => sha256(message).to_vec(),
                HashAlgorithm::Sha384 => sha384(message).to_vec(),
                HashAlgorithm::Sha512 => sha512(message).to_vec(),
                _ => unreachable!() 
            };

            let salt_length = determine_salt_length(&hash_algorithm)
                .map_err(|_| SymCryptError::InvalidArgument)?; 

            rsa_key.pss_verify(&hashed_message, &signature, hash_algorithm, salt_length)
        },
        _ => {
            println!("Unsupported RSA PSS hash algorithm");
            return Err(SymCryptError::InvalidArgument);
        }
    };

    verify_result.map_err(|e| {
        println!("Verification failed with error: {:?}", e);
        e
    }).map(|_| {
        println!("Verification successful.");
    })
}

/// Handles ECC signature verification.
///
/// This function verifies an ECDSA signature using the specified curve type
///
/// # Parameters:
/// * `signature`: A `Vec<u8>` containing the signature to be verified
/// * `curve_type`: The elliptic curve type, specified by [`CurveType`]
/// * `_hash_algorithm`: The hash algorithm used for hashing the message
/// * `key`: The elliptic curve key used for the verification
/// * `message`: A slice of bytes (`&[u8]`) representing the original message that was signed
///
/// # Returns:
/// A `Result<(), SymCryptError>` that indicates the success or failure of the signature verification
/// Returns `Ok(())` if the signature is verified successfully, and an `Err(SymCryptError)` for any errors encountered during verification
fn handle_ecc(signature: Vec<u8>, curve_type: CurveType, _hash_algorithm: HashAlgorithm, key: EcKey, message: &[u8]) -> Result<(), SymCryptError> {
    let verify_result = match curve_type {
        CurveType::NistP256 => {
            let hashed_message_256 = sha256(message);
            key.ecdsa_verify(&signature, &hashed_message_256)
        },
        CurveType::NistP384 => {
            let hashed_message_384 = sha384(message);
            key.ecdsa_verify(&signature, &hashed_message_384)
        },
        CurveType::Curve25519 => {
            println!("Curve25519 is not supported for ECDSA verification.");
            return Err(SymCryptError::InvalidArgument);
        },
    };

    verify_result.map_err(|e| {
        println!("Verification failed with error: {:?}", e);
        e
    }).map(|_| {
        println!("Verification successful.");
    })
}

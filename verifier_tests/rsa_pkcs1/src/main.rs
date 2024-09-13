#![allow(warnings)]
use std::fs;
use rsa::traits::PrivateKeyParts;
use rsa::traits::PublicKeyParts;
use x509_parser::prelude::*;
use der::{asn1::Uint, Decode, Reader};
use std::error::Error;
use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey};

use rust_symcrypt_asn_verifier::{
    HashAlgorithm, 
    sha256, sha384, sha512, 
    SHA256_RESULT_SIZE, SHA384_RESULT_SIZE, SHA512_RESULT_SIZE,
    parse_certificate,
    x509::SignatureScheme,
};

use symcrypt::rsa::{
    RsaKey, 
    RsaKeyUsage,
};

#[derive(Debug)]
pub struct RSAPublicKey {
    pub modulus: Uint,
    pub exponent: Uint,
}

impl<'a> Decode<'a> for RSAPublicKey {
    fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        reader.sequence(|reader| {
            let modulus = reader.decode()?;
            let exponent = reader.decode()?;
            Ok(RSAPublicKey { modulus, exponent })
        })
    }
}

fn load_rsa_private_key(path: &str) -> RsaPrivateKey {
    let der_bytes = fs::read(path).expect("Failed to read private key file");
    RsaPrivateKey::from_pkcs8_der(&der_bytes).expect("Failed to parse private key")
}

fn main() -> Result<(), Box<dyn Error>> {
    // Create a message to sign
    let message = b"Example message for testing";
    let hashed_message = sha384(message);
    let hash_algorithm = HashAlgorithm::Sha384;

    // Import the RSA key from the .key file
    let private_key = load_rsa_private_key(r"C:\temp\localhost.key.der");

    // Extract the primes, modulus, and exponent from the private key
    let private_modulus = private_key.n();
    let private_exponent = private_key.e();
    let p = private_key.primes().get(0).unwrap();
    let q = private_key.primes().get(1).unwrap();
    
    // Create a new RSA key pair from the extracted values
    let key_pair = RsaKey::set_key_pair(&private_modulus.to_bytes_be(), &private_exponent.to_bytes_be(), &p.to_bytes_be(), &q.to_bytes_be(), RsaKeyUsage::SignAndEncrypt).unwrap();
    
    // Create a signature for the message
    let signature = key_pair.pkcs1_sign(&hashed_message, hash_algorithm).unwrap();

    // Parse the certificate and extract the public key
    let path_new = r"C:\temp\localhost.der";
    let data_new = fs::read(path_new).expect("Failed to read test certificate file");
    let (_, cert) = X509Certificate::from_der(&data_new)?;
    let spki = &cert.tbs_certificate.subject_pki;

    // Extract the public key from the certificate
    let rsa_public_key = RSAPublicKey::from_der(&spki.subject_public_key.data)?;

    // Create a new RSA key using set_public_key
    let rsa_key = RsaKey::set_public_key(
        &rsa_public_key.modulus.as_bytes(),
        &rsa_public_key.exponent.as_bytes(),
        RsaKeyUsage::SignAndEncrypt,
    )
    .unwrap();
    let fake_message = b"Fake message for testing";
    let sig_scheme = SignatureScheme::RSA_PKCS1_SHA256;

    parse_certificate(&data_new, message, signature, sig_scheme).unwrap();

    Ok(())
}
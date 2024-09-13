#![allow(warnings)]
use picky_asn1_der::{from_bytes, Asn1DerError};
use picky_asn1_x509::{PrivateKeyInfo, PrivateKeyValue};
use std::fs::File;
use std::io::{self, Read};
use std::fs;
use std::path::Path;
use symcrypt::ecc::EcKey;
use symcrypt::ecc::CurveType;
use symcrypt::ecc::EcKeyUsage;
use x509_parser::prelude::*;

use rust_symcrypt_asn_verifier::{
    sha256,
    parse_certificate,
    x509::SignatureScheme,
};

fn read_key_file(path: &Path) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let private_key_info: Result<PrivateKeyInfo, Asn1DerError> = from_bytes(&buffer);
    match private_key_info {
        Ok(info) => {
            match &info.private_key {
                PrivateKeyValue::EC(ec_private_key) => {
                    let bytes_result: Result<Vec<u8>, io::Error> = ec_private_key.private_key.bytes().collect();
                    match bytes_result {
                        Ok(bytes_vec) => {
                            return Ok(bytes_vec); 
                        },
                        Err(e) => {
                            println!("Error reading bytes: {:?}", e);
                            return Err(e);
                        }
                    }
                },
                _ => {
                    println!("Not an ecc private key");
                    return Err(io::Error::new(io::ErrorKind::Other, "Unsupported key type"));
                }
            }
        },
        Err(e) => {
            println!("Failed to parse key: {:?}", e);
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to parse key"));
        }
    }
}

// fn print_signature(data: &[u8]) -> Result<(), &'static str> {
//     let (remaining_data, cert) = X509Certificate::from_der(data).map_err(|_| "Failed to parse certificate")?;
//     let tbs = &data[..data.len() - remaining_data.len()];

    
//     println!("Signature Bytes: {:?}", cert.signature_value.data);

//     parse_certificate(&data, tbs, cert.signature_value.data.to_vec(), SignatureScheme::ECDSA_NISTP256_SHA256).unwrap();

//     Ok(())
// }

fn strip_leading_zeros(bytes: &[u8]) -> Vec<u8> {
    // Skip leading zeros while ensuring at least one byte remains
    let first_significant_byte = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
    bytes[first_significant_byte..].to_vec()
}

fn main() {
    let path = Path::new(r"C:\temp\end.key.der");
    // let cert = Path::new(r"C:\temp\ca.der");

    // match fs::read(&cert) {
    //     Ok(data) => {
    //         if let Err(e) = print_signature(&data) {
    //             eprintln!("Error extracting signature: {}", e);
    //         }
    //     },
    //     Err(e) => eprintln!("Failed to read file: {}", e),
    // }

    match read_key_file(&path) {
        Ok(bytes_vec) => {
            let message = b"example message for testing";
            let cert_path = Path::new(r"C:\temp\end.der");

            match fs::read(cert_path) {
                Ok(data_ecc) => {
                    let keys = EcKey::set_key_pair(CurveType::NistP256, &bytes_vec, None, EcKeyUsage::EcDsa).unwrap();
                    let hash_value = sha256(message);
                    let eccsig = keys.ecdsa_sign(&hash_value).unwrap();
                    let fake_message = b"Fake example message for testing";
                    parse_certificate(&data_ecc, fake_message, eccsig.to_vec(), SignatureScheme::ECDSA_NISTP256_SHA256).unwrap();
                    
                },
                Err(e) => eprintln!("Failed to read certificate file: {}", e),
            }
        },
        Err(e) => eprintln!("Failed to read key file: {}", e),
    }


}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_read_key_file_valid() {
        let path = Path::new(r"C:\temp\end.key.der");  // Adjust the path to your test file
        assert!(read_key_file(&path).is_ok());
    }

    #[test]
    fn test_read_key_file_invalid() {
        let path = Path::new(r"C:\temp\localhost.key.der");  // Adjust to point to an intentionally bad or non-ECC key
        assert!(read_key_file(&path).is_err());
    }
}

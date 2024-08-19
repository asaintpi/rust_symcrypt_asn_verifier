# Rust SymCrypt ASN Verifier

This Rust project provides cryptographic verification functionalities tailored specifically for X.509 certificates. It supports various RSA and ECDSA signature schemes utilizing the cryptographic backend provided by `symcrypt`.

## Features

- Supports parsing and verifying X.509 certificates.
- Implements RSA PKCS#1, RSA PSS, and ECDSA signature schemes.
- Handles different hash algorithms including SHA-256, SHA-384, and SHA-512.
- Supports NIST P-256 and P-384 elliptic curve standards.

## Dependencies
This project relies on the following crates:
- `symcrypt`
- `der`
- `x509-parser`

Ensure these are included in your `Cargo.toml`:

```toml
[dependencies]
symcrypt = "0.1"
der = "0.1"
x509-parser = "0.1"
```

## Setup and Usage
```
git clone https://github.com/yourusername/rust_symcrypt_asn_verifier.git
cd rust_symcrypt_asn_verifier
```

 ## Building the Project
 Compile the project using Cargo
 ```
cargo build --release
```

## Running Tests
Run the predefined tests
```
cargo test -- --nocapture
```

## API Overview
Key Functions
-  `parse_x509_certificate`: Parses X.509 certificates for RSA signature verification.
-  `parse_x509_certificate_ec`: Parses X.509 certificates for ECDSA signature verification.
-  `handle_rsa`: Handles RSA signature verification.
-  `handle_rsa_pss`: Handles RSA-PSS signature verification.
-  `handle_ecc`: Handles ECDSA signature verification.

## Example Usage
```
// Example for PKCS#1 (Psuedo)
let message = b"..."
let hash_algorithm = Sha384
let private_key = {... load private key ...}
let signature_scheme = SignatureScheme::RSA_PKCS1_SHA384

let key_pair = {... create key pair from private key data ...}
let signature = {... generate a signature using key pair ...}

let certifcate = {temp/files/certificate.der}
let certificate_data = read(certificate)
let rsa_public_key = {... generate key from spki ...}
let rsa_key = {create public key from: rsa_public_key modulus/exponent}

parse_certificate(&certificate_data, message, signature, signature_scheme, Some(rsa_key), None).unwrap()
// This will display success of failure
```


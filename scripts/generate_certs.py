"""
Certificate Generation Script

Generates self-signed certificates for testing the VPN locally.
Uses the cryptography library for cross-platform compatibility.
"""

import os
import datetime
import ipaddress
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_private_key() -> rsa.RSAPrivateKey:
    """Generate a 2048-bit RSA private key."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


def generate_certificate(
    private_key: rsa.RSAPrivateKey,
    common_name: str,
    is_ca: bool = False,
    ca_cert: x509.Certificate = None,
    ca_key: rsa.RSAPrivateKey = None,
) -> x509.Certificate:
    """
    Generate a self-signed certificate or sign with CA.
    
    Args:
        private_key: Private key for the certificate
        common_name: Common name for the certificate
        is_ca: Whether this is a CA certificate
        ca_cert: CA certificate for signing (if not self-signed)
        ca_key: CA private key for signing (if not self-signed)
    
    Returns:
        Generated certificate
    """
    # create subject and issuer names
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "kimoVPN"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    if ca_cert and ca_key:
        issuer = ca_cert.subject
        signing_key = ca_key
    else:
        issuer = subject
        signing_key = private_key
    
    # create certificate builder
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    builder = builder.not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    )
    
    # add extensions
    if is_ca:
        # ca certificate extensions
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        # server certificate extensions
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # add subject alternative names for localhost
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("127.0.0.1"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
    
    # sign the certificate
    certificate = builder.sign(signing_key, hashes.SHA256())
    
    return certificate


def save_private_key(key: rsa.RSAPrivateKey, filepath: Path, password: bytes = None):
    """
    Save private key to file.
    
    Args:
        key: Private key to save
        filepath: Path to save the key
        password: Optional password for encryption
    """
    if password:
        encryption = serialization.BestAvailableEncryption(password)
    else:
        encryption = serialization.NoEncryption()
    
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=encryption,
    )
    
    filepath.write_bytes(pem)
    print(f"Saved private key: {filepath}")


def save_certificate(cert: x509.Certificate, filepath: Path):
    """
    Save certificate to file.
    
    Args:
        cert: Certificate to save
        filepath: Path to save the certificate
    """
    pem = cert.public_bytes(serialization.Encoding.PEM)
    filepath.write_bytes(pem)
    print(f"Saved certificate: {filepath}")


def main():
    """Generate all required certificates for testing."""
    # ensure certs directory exists
    certs_dir = Path("certs")
    certs_dir.mkdir(exist_ok=True)
    
    print("Generating certificates for kimoVPN...")
    print("-" * 50)
    
    # generate ca certificate
    print("\n1. Generating CA certificate...")
    ca_key = generate_private_key()
    ca_cert = generate_certificate(ca_key, "kimoVPN CA", is_ca=True)
    
    save_private_key(ca_key, certs_dir / "ca.key")
    save_certificate(ca_cert, certs_dir / "ca.crt")
    
    # generate server certificate
    print("\n2. Generating server certificate...")
    server_key = generate_private_key()
    server_cert = generate_certificate(
        server_key, 
        "localhost",
        is_ca=False,
        ca_cert=ca_cert,
        ca_key=ca_key
    )
    
    save_private_key(server_key, certs_dir / "server.key")
    save_certificate(server_cert, certs_dir / "server.crt")
    
    # generate client certificate (optional, for mutual tls)
    print("\n3. Generating client certificate...")
    client_key = generate_private_key()
    client_cert = generate_certificate(
        client_key,
        "kimoVPN Client",
        is_ca=False,
        ca_cert=ca_cert,
        ca_key=ca_key
    )
    
    save_private_key(client_key, certs_dir / "client.key")
    save_certificate(client_cert, certs_dir / "client.crt")
    
    print("\n" + "=" * 50)
    print("Certificate generation complete!")
    print("=" * 50)
    print("\nGenerated files:")
    print("  CA Certificate:     certs/ca.crt")
    print("  CA Private Key:     certs/ca.key")
    print("  Server Certificate: certs/server.crt")
    print("  Server Private Key: certs/server.key")
    print("  Client Certificate: certs/client.crt")
    print("  Client Private Key: certs/client.key")
    print("\nThese certificates are for TESTING ONLY.")
    print("Do not use in production environments.")


if __name__ == "__main__":
    main()
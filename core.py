"""
Provides the core certificate-generation logic for ssl_maker:
- CertConfig: holds and validates CA / certificate parameters
- SSLCertificateMakerEngine: creates, cleans, and signs self-signed CAs and leaf certs
"""

import os
import re
import datetime
from dataclasses import dataclass
from pathlib import Path
import ipaddress
import logging

from cryptography import x509
from cryptography.x509 import random_serial_number
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    BestAvailableEncryption,
    NoEncryption,
    pkcs12,
)

logger = logging.getLogger(__name__)


@dataclass
class CertConfig:
    """
    Configuration for certificate generation.

    Attributes:
        ca_name: Common Name for the root CA.
        country: 2-letter country code (e.g. 'US', 'JP').
        state: State or province name.
        locality: City or locality name.
        organization: Organization name.
        unit: Organizational unit.
        email: Contact email address.
        domain: The domain (or IP) for which to issue a certificate.
        password: Password to encrypt private keys / PFX archives.
        output_dir: Directory in which to write all artifacts.
    """

    ca_name: str
    country: str
    state: str
    locality: str
    organization: str
    unit: str
    email: str
    domain: str
    password: bytes
    output_dir: Path

    def validate(self) -> None:
        """
        Validate required fields, and ensure the domain is a valid hostname or IP.

        Raises:
            ValueError: if any mandatory field is missing or domain is invalid.
        """
        if not self.ca_name:
            raise ValueError("CA name cannot be empty")
        if not self.domain:
            raise ValueError("Domain cannot be empty")

        # domain can be a literal IP or a DNS name
        try:
            ipaddress.ip_address(self.domain)
        except ValueError:
            if not re.match(r'^(?:[A-Za-z0-9-]+\.)*[A-Za-z0-9-]+$', self.domain):
                raise ValueError(f"Invalid domain name: {self.domain}")


class SSLCertificateMakerEngine:
    """
    Engine to generate, sign, and manage self-signed SSL certificates.

    Usage:
        config = CertConfig(...)
        engine = SSLCertificateMakerEngine(config)
        engine.run()
    """

    def __init__(self, config: CertConfig) -> None:
        """
        Initialize engine, ensure output directory exists, and sanitize CA name.

        Args:
            config: CertConfig instance with generation parameters.
        """
        self.config = config
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        # sanitize CA name for filenames
        self.safe_ca_name = re.sub(r'[^A-Za-z0-9_-]', '_', self.config.ca_name)

    def _next_serial(self) -> int:
        """
        Return a new random serial number for certificates.
        """
        return random_serial_number()

    def clean_certificates(self) -> None:
        """
        Remove any existing certificate, key, CSR, PEM, or PFX files
        in the output directory to start fresh.
        """
        for pattern in ("*.crt", "*.key", "*.csr", "*.pem", "*.pfx"):
            for file in self.config.output_dir.glob(pattern):
                try:
                    file.unlink()
                except OSError:
                    logger.warning(f"Failed to remove {file}")
        logger.info("Removed existing certificate files")

    def generate_root_ca(self) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """
        Generate a new RSA 2048-bit key and self-signed root CA certificate.

        Writes:
            <safe_ca_name>.key  — encrypted with the provided password
            <safe_ca_name>.crt  — the PEM-encoded cert

        Returns:
            A tuple of (private_key, certificate).
        """
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"{self.safe_ca_name}_selfCA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.config.organization),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.config.unit),
        ])
        builder = x509.CertificateBuilder().subject_name(name).issuer_name(name)
        builder = builder.not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365*100))
        builder = builder.serial_number(self._next_serial()).public_key(key.public_key())
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)

        cert = builder.sign(private_key=key, algorithm=hashes.SHA256())

        key_path = self.config.output_dir / f"{self.safe_ca_name}.key"
        cert_path = self.config.output_dir / f"{self.safe_ca_name}.crt"
        key_bytes = key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=BestAvailableEncryption(self.config.password),
        )
        key_path.write_bytes(key_bytes)
        os.chmod(key_path, 0o600)
        cert_path.write_bytes(cert.public_bytes(Encoding.PEM))
        logger.info(f"Generated root CA key at {key_path} and certificate at {cert_path}")
        return key, cert

    def generate_key(self, domain: str) -> rsa.RSAPrivateKey:
        """
        Generate a new RSA 2048-bit private key for a leaf certificate,
        write it unencrypted to <domain>.key, and return the key object.
        """
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption(),
        )
        key_path = self.config.output_dir / f"{domain}.key"
        key_path.write_bytes(pem)
        os.chmod(key_path, 0o600)
        logger.info(f"Generated domain key at {key_path}")
        return key

    def generate_csr(
        self,
        key: rsa.RSAPrivateKey,
        domain: str
    ) -> x509.CertificateSigningRequest:
        """
        Create a CSR (Certificate Signing Request) for the given key and domain,
        write it to <domain>.csr, and return the CSR object.
        """
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.config.country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.config.state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, self.config.locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.config.organization),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, self.config.email),
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
        ])
        csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
            key, hashes.SHA256()
        )
        csr_path = self.config.output_dir / f"{domain}.csr"
        csr_path.write_bytes(csr.public_bytes(Encoding.PEM))
        logger.info(f"Generated CSR at {csr_path}")
        return csr

    def sign_certificate(
        self,
        csr: x509.CertificateSigningRequest,
        root_key: rsa.RSAPrivateKey,
        root_cert: x509.Certificate,
        client_key: rsa.RSAPrivateKey,
        domain: str
    ) -> None:
        """
        Sign the CSR with the root CA to produce a leaf certificate.

        - Builds appropriate SAN entries (DNS / IP / localhost)
        - Writes <domain>.crt and <domain>.pem
        - Calls create_pfx() to produce <domain>.pfx
        """
        san_list = []
        try:
            ip = ipaddress.ip_address(domain)
            san_list.append(x509.IPAddress(ip))
            san_list.append(x509.DNSName(str(ip)))
            if ip.is_loopback:
                san_list.append(x509.DNSName("localhost"))
        except ValueError:
            san_list.append(x509.DNSName(domain))

        builder = x509.CertificateBuilder() \
            .subject_name(csr.subject) \
            .issuer_name(root_cert.subject) \
            .public_key(csr.public_key()) \
            .serial_number(self._next_serial()) \
            .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1)) \
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365*100)) \
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
            .add_extension(x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=True,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
                key_cert_sign=False,
                crl_sign=False,
            ), critical=True) \
            .add_extension(x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH,
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CODE_SIGNING,
            ]), critical=True) \
            .add_extension(x509.SubjectAlternativeName(san_list), critical=False) \
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
                critical=False
            )

        cert = builder.sign(private_key=root_key, algorithm=hashes.SHA256())

        crt_path = self.config.output_dir / f"{domain}.crt"
        pem_path = self.config.output_dir / f"{domain}.pem"
        crt_path.write_bytes(cert.public_bytes(Encoding.PEM))
        pem_path.write_bytes(cert.public_bytes(Encoding.PEM))
        logger.info(f"Signed certificate for {domain} at {crt_path}")
        self.create_pfx(client_key, cert, domain)

    def create_pfx(
        self,
        key: rsa.RSAPrivateKey,
        cert: x509.Certificate,
        domain: str
    ) -> None:
        """
        Package the private key and leaf certificate into a PFX archive,
        encrypted with the configured password, and write <domain>.pfx.
        """
        pfx_data = pkcs12.serialize_key_and_certificates(
            name=b"",
            key=key,
            cert=cert,
            cas=None,
            encryption_algorithm=BestAvailableEncryption(self.config.password),
        )
        pfx_path = self.config.output_dir / f"{domain}.pfx"
        pfx_path.write_bytes(pfx_data)
        logger.info(f"Created PFX archive at {pfx_path}")

    def run(self) -> None:
        """
        Full workflow: validate config, wipe old files, generate root CA,
        leaf key, CSR, sign leaf certificate, and produce PFX.
        """
        self.config.validate()
        self.clean_certificates()
        root_key, root_cert = self.generate_root_ca()
        client_key = self.generate_key(self.config.domain)
        csr = self.generate_csr(client_key, self.config.domain)
        self.sign_certificate(csr, root_key, root_cert, client_key, self.config.domain)

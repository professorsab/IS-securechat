from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import datetime
import sys

def load_ca():
    with open("certs/ca_cert.pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open("certs/ca_private.pem", "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    return ca_cert, ca_key

def generate_cert(common_name, cert_type):
    ca_cert, ca_key = load_ca()
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Create certificate
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(ca_key, hashes.SHA256())
    
    # Save files
    with open(f"certs/{cert_type}_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open(f"certs/{cert_type}_cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"{cert_type} certificate generated successfully!")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python gen_cert.py <common_name> <server|client>")
        sys.exit(1)
    
    generate_cert(sys.argv[1], sys.argv[2])
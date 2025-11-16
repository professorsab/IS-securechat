from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import datetime

class PKIValidator:
    """Certificate validation and PKI operations"""
    
    @staticmethod
    def load_certificate(cert_pem):
        """
        Load X.509 certificate from PEM format
        
        Args:
            cert_pem: Certificate in PEM format (string or bytes)
            
        Returns:
            Certificate object
        """
        if isinstance(cert_pem, str):
            cert_pem = cert_pem.encode()
        return x509.load_pem_x509_certificate(cert_pem)
    
    @staticmethod
    def verify_certificate(cert_pem, ca_cert_pem):
        """
        Verify certificate signature, validity period, and chain
        
        Args:
            cert_pem: Certificate to verify (PEM format)
            ca_cert_pem: CA certificate (PEM format)
            
        Returns:
            (bool, str): (is_valid, message)
        """
        try:
            cert = PKIValidator.load_certificate(cert_pem)
            ca_cert = PKIValidator.load_certificate(ca_cert_pem)
        except Exception as e:
            return False, f"BAD_CERT: Failed to load certificate - {str(e)}"
        
        # 1. Verify signature chain
        try:
            ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
        except Exception as e:
            return False, f"BAD_CERT: Invalid signature - {str(e)}"
        
        # 2. Check validity period
        now = datetime.datetime.utcnow()
        if now < cert.not_valid_before:
            return False, "BAD_CERT: Certificate not yet valid"
        
        if now > cert.not_valid_after:
            return False, "BAD_CERT: Certificate expired"
        
        # 3. Verify issuer
        if cert.issuer != ca_cert.subject:
            return False, "BAD_CERT: Issuer mismatch"
        
        return True, "CERT_VALID"
    
    @staticmethod
    def get_certificate_fingerprint(cert_pem):
        """
        Get SHA-256 fingerprint of certificate
        
        Args:
            cert_pem: Certificate in PEM format
            
        Returns:
            Hex string of certificate fingerprint
        """
        cert = PKIValidator.load_certificate(cert_pem)
        fingerprint = cert.fingerprint(hashes.SHA256())
        return fingerprint.hex()
    
    @staticmethod
    def extract_public_key(cert_pem):
        """
        Extract public key from certificate
        
        Args:
            cert_pem: Certificate in PEM format
            
        Returns:
            Public key object
        """
        cert = PKIValidator.load_certificate(cert_pem)
        return cert.public_key()
    
    @staticmethod
    def get_common_name(cert_pem):
        """
        Extract Common Name from certificate
        
        Args:
            cert_pem: Certificate in PEM format
            
        Returns:
            Common Name (str)
        """
        cert = PKIValidator.load_certificate(cert_pem)
        for attribute in cert.subject:
            if attribute.oid == x509.NameOID.COMMON_NAME:
                return attribute.value
        return None
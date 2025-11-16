from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import hashlib

class DigitalSignature:
    """RSA digital signature operations"""
    
    @staticmethod
    def compute_message_digest(seqno, timestamp, ciphertext):
        """
        Compute SHA-256 digest for message authentication
        
        Format: SHA256(seqno || timestamp || ciphertext)
        
        Args:
            seqno: Sequence number (int)
            timestamp: Unix timestamp in milliseconds (int)
            ciphertext: Encrypted message (bytes)
            
        Returns:
            SHA-256 digest (bytes)
        """
        # Concatenate: seqno || timestamp || ciphertext
        data = str(seqno).encode() + str(timestamp).encode() + ciphertext
        
        # Compute SHA-256
        digest = hashlib.sha256(data).digest()
        
        return digest
    
    @staticmethod
    def sign(private_key, data):
        """
        Sign data using RSA private key
        
        Args:
            private_key: RSA private key object
            data: Data to sign (bytes)
            
        Returns:
            Digital signature (bytes)
        """
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    @staticmethod
    def verify(public_key, signature, data):
        """
        Verify RSA signature
        
        Args:
            public_key: RSA public key object
            signature: Signature to verify (bytes)
            data: Original data (bytes)
            
        Returns:
            bool: True if valid, False otherwise
        """
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    @staticmethod
    def sign_message(private_key, seqno, timestamp, ciphertext):
        """
        Complete message signing workflow
        
        Args:
            private_key: RSA private key
            seqno: Sequence number
            timestamp: Unix timestamp (ms)
            ciphertext: Encrypted message
            
        Returns:
            Digital signature (bytes)
        """
        digest = DigitalSignature.compute_message_digest(seqno, timestamp, ciphertext)
        signature = DigitalSignature.sign(private_key, digest)
        return signature
    
    @staticmethod
    def verify_message(public_key, signature, seqno, timestamp, ciphertext):
        """
        Complete message verification workflow
        
        Args:
            public_key: RSA public key
            signature: Signature to verify
            seqno: Sequence number
            timestamp: Unix timestamp (ms)
            ciphertext: Encrypted message
            
        Returns:
            bool: True if valid
        """
        digest = DigitalSignature.compute_message_digest(seqno, timestamp, ciphertext)
        return DigitalSignature.verify(public_key, signature, digest)
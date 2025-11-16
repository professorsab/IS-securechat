import os
from cryptography.hazmat.primitives import hashes

class DiffieHellman:
    """Basic Diffie-Hellman key exchange implementation"""
    
    # Safe prime and generator (2048-bit for security)
    # These are publicly known parameters
    DEFAULT_P = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
    )
    DEFAULT_G = 2
    
    def __init__(self, p=None, g=None):
        """
        Initialize DH with parameters
        
        Args:
            p: Prime modulus (use default if None)
            g: Generator (use default if None)
        """
        self.p = p or self.DEFAULT_P
        self.g = g or self.DEFAULT_G
        self.private_key = None
        self.public_key = None
    
    def generate_private_key(self):
        """Generate random private key"""
        # Private key should be in range [2, p-2]
        key_size = (self.p.bit_length() + 7) // 8
        self.private_key = int.from_bytes(os.urandom(key_size), 'big') % (self.p - 2) + 2
        return self.private_key
    
    def generate_public_key(self):
        """
        Generate public key: g^private_key mod p
        
        Returns:
            Public key (integer)
        """
        if self.private_key is None:
            self.generate_private_key()
        
        self.public_key = pow(self.g, self.private_key, self.p)
        return self.public_key
    
    def compute_shared_secret(self, peer_public_key):
        """
        Compute shared secret: peer_public_key^private_key mod p
        
        Args:
            peer_public_key: Other party's public key (integer)
            
        Returns:
            Shared secret (integer)
        """
        if self.private_key is None:
            raise ValueError("Private key not generated")
        
        shared_secret = pow(peer_public_key, self.private_key, self.p)
        return shared_secret
    
    @staticmethod
    def derive_aes_key(shared_secret):
        """
        Derive AES-128 key from shared secret using SHA-256
        
        Formula: K = Trunc_16(SHA256(big-endian(Ks)))
        
        Args:
            shared_secret: DH shared secret (integer)
            
        Returns:
            16-byte AES key
        """
        # Convert shared secret to big-endian bytes
        secret_bytes = shared_secret.to_bytes(
            (shared_secret.bit_length() + 7) // 8, 
            'big'
        )
        
        # Hash with SHA-256
        digest = hashes.Hash(hashes.SHA256())
        digest.update(secret_bytes)
        hash_output = digest.finalize()
        
        # Truncate to 16 bytes for AES-128
        aes_key = hash_output[:16]
        
        return aes_key
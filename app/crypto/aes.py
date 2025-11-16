from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

class AESCipher:
    """AES-128 encryption using CBC mode with PKCS7 padding"""
    
    @staticmethod
    def pad_pkcs7(data, block_size=16):
        """Apply PKCS#7 padding to data"""
        if isinstance(data, str):
            data = data.encode()
        padding_len = block_size - (len(data) % block_size)
        padding = bytes([padding_len] * padding_len)
        return data + padding
    
    @staticmethod
    def unpad_pkcs7(data):
        """Remove PKCS#7 padding from data"""
        padding_len = data[-1]
        if padding_len > 16 or padding_len == 0:
            raise ValueError("Invalid PKCS7 padding")
        # Verify all padding bytes are correct
        if data[-padding_len:] != bytes([padding_len] * padding_len):
            raise ValueError("Invalid PKCS7 padding")
        return data[:-padding_len]
    
    @staticmethod
    def encrypt(plaintext, key):
        """
        Encrypt plaintext using AES-128 CBC mode
        
        Args:
            plaintext: String or bytes to encrypt
            key: 16-byte AES key
            
        Returns:
            IV (16 bytes) + Ciphertext
        """
        if len(key) != 16:
            raise ValueError("AES-128 requires 16-byte key")
        
        # Generate random IV
        iv = os.urandom(16)
        
        # Pad plaintext
        padded_data = AESCipher.pad_pkcs7(plaintext)
        
        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return IV + ciphertext
        return iv + ciphertext
    
    @staticmethod
    def decrypt(ciphertext_with_iv, key):
        """
        Decrypt ciphertext using AES-128 CBC mode
        
        Args:
            ciphertext_with_iv: IV (16 bytes) + Ciphertext
            key: 16-byte AES key
            
        Returns:
            Decrypted plaintext as bytes
        """
        if len(key) != 16:
            raise ValueError("AES-128 requires 16-byte key")
        
        if len(ciphertext_with_iv) < 16:
            raise ValueError("Ciphertext too short")
        
        # Extract IV and ciphertext
        iv = ciphertext_with_iv[:16]
        ciphertext = ciphertext_with_iv[16:]
        
        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        plaintext = AESCipher.unpad_pkcs7(padded_plaintext)
        
        return plaintext
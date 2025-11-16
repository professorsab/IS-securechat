# Import from crypto modules
from crypto.aes import AESCipher
from crypto.dh import DiffieHellman
from crypto.pki import PKIValidator
from crypto.sign import DigitalSignature

# Import from common
from common.protocol import Protocol
from common.utils import Utils

# Import from storage
from storage.db import DatabaseManager
from storage.transcript import TranscriptManager
# src/server.py
import socket
import json
import base64
import os
import time

from crypto.aes import AESCipher
from crypto.dh import DiffieHellman
from crypto.pki import PKIValidator
from crypto.sign import DigitalSignature
from storage.db import DatabaseManager
from storage.transcript import TranscriptManager
from common.protocol import Protocol

class SecureServer:
    def __init__(self, host='localhost', port=8888):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.db = DatabaseManager()
        self.transcript = TranscriptManager("server")
        self.load_credentials()
        
    def load_credentials(self):
        """Load server certificate and private key"""
        with open("certs/server_cert.pem", "r") as f:
            self.cert_pem = f.read()
        
        with open("certs/server_private.pem", "rb") as f:
            from cryptography.hazmat.primitives import serialization
            self.private_key = serialization.load_pem_private_key(
                f.read(), 
                password=None
            )
        
        with open("certs/ca_cert.pem", "r") as f:
            self.ca_cert_pem = f.read()
    
    def handle_certificate_exchange(self, conn):
        """Phase 1: Certificate exchange and validation"""
        # Receive client hello
        client_hello = json.loads(conn.recv(4096).decode())
        client_cert_pem = client_hello['client_cert']
        
        # Validate client certificate
        is_valid, msg = PKIValidator.verify_certificate(
            client_cert_pem, 
            self.ca_cert_pem
        )
        
        if not is_valid:
            error = {"type": "error", "msg": msg}
            conn.send(json.dumps(error).encode())
            return None, None
        
        # Send server hello
        server_hello = {
            "type": "server_hello",
            "server_cert": self.cert_pem,
            "nonce": base64.b64encode(os.urandom(16)).decode()
        }
        conn.send(json.dumps(server_hello).encode())
        
        # Extract client public key for later signature verification
        client_public_key = PKIValidator.extract_public_key(client_cert_pem)
        
        return client_cert_pem, client_public_key
    
    def handle_auth_dh(self, conn):
        """Phase 2: DH key exchange for authentication"""
        # Receive client DH parameters
        dh_client = json.loads(conn.recv(4096).decode())
        p = dh_client['p']
        g = dh_client['g']
        A = dh_client['A']
        
        # Generate server DH keys
        dh = DiffieHellman(p, g)
        dh.generate_private_key()
        B = dh.generate_public_key()
        
        # Send server DH public key
        dh_server = {"type": "dh_server", "B": B}
        conn.send(json.dumps(dh_server).encode())
        
        # Compute shared secret and derive AES key
        shared_secret = dh.compute_shared_secret(A)
        auth_key = DiffieHellman.derive_aes_key(shared_secret)
        
        return auth_key
    
    def handle_registration(self, conn, auth_key):
        """Phase 3: Handle registration or login"""
        # Receive encrypted auth message
        auth_msg = json.loads(conn.recv(4096).decode())
        encrypted_data = base64.b64decode(auth_msg['data'])
        
        # Decrypt using auth key
        decrypted = AESCipher.decrypt(encrypted_data, auth_key)
        auth_data = json.loads(decrypted.decode())
        
        if auth_data['type'] == 'register':
            success = self.db.register_user(
                auth_data['email'],
                auth_data['username'],
                base64.b64decode(auth_data['salt']),
                auth_data['pwd']
            )
            response = {
                "type": "register_response", 
                "success": success,
                "msg": "Registration successful" if success else "User already exists"
            }
        
        elif auth_data['type'] == 'login':
            # Verify password
            success = self.db.verify_login(
                auth_data['email'],
                auth_data['pwd']
            )
            response = {
                "type": "login_response",
                "success": success,
                "msg": "Login successful" if success else "Invalid credentials"
            }
        
        # Encrypt response
        encrypted_response = AESCipher.encrypt(
            json.dumps(response).encode(),
            auth_key
        )
        conn.send(base64.b64encode(encrypted_response))
        
        return response['success']
    
    def handle_chat_dh(self, conn):
        """Phase 4: DH key exchange for chat session"""
        # New DH exchange for chat
        dh_client = json.loads(conn.recv(4096).decode())
        p = dh_client['p']
        g = dh_client['g']
        A = dh_client['A']
        
        dh = DiffieHellman(p, g)
        dh.generate_private_key()
        B = dh.generate_public_key()
        
        dh_server = {"type": "dh_server", "B": B}
        conn.send(json.dumps(dh_server).encode())
        
        shared_secret = dh.compute_shared_secret(A)
        session_key = DiffieHellman.derive_aes_key(shared_secret)
        
        return session_key
    
    def chat_loop(self, conn, session_key, client_public_key, client_cert_pem):
        """Phase 5: Encrypted chat with integrity checks"""
        seqno_received = 0
        cert_fingerprint = PKIValidator.get_certificate_fingerprint(client_cert_pem)
        
        print("\n[SERVER] Chat session started. Type messages or 'quit' to exit.\n")
        
        while True:
            try:
                # Receive message
                data = conn.recv(4096)
                if not data:
                    break
                
                msg = json.loads(data.decode())
                
                if msg['type'] == 'msg':
                    seqno = msg['seqno']
                    ts = msg['ts']
                    ct = base64.b64decode(msg['ct'])
                    sig = base64.b64decode(msg['sig'])
                    
                    # Replay protection
                    if seqno <= seqno_received:
                        print(f"[SECURITY] REPLAY ATTACK DETECTED: seqno={seqno}")
                        continue
                    
                    # Verify signature
                    if not DigitalSignature.verify_message(
                        client_public_key, sig, seqno, ts, ct
                    ):
                        print(f"[SECURITY] SIG_FAIL: Invalid signature on message {seqno}")
                        continue
                    
                    # Decrypt message
                    plaintext = AESCipher.decrypt(ct, session_key)
                    print(f"[CLIENT]: {plaintext.decode()}")
                    
                    # Update sequence
                    seqno_received = seqno
                    
                    # Log to transcript
                    self.transcript.add_entry(
                        seqno, ts, ct, sig, cert_fingerprint
                    )
                
                elif msg['type'] == 'close':
                    print("\n[SERVER] Client disconnected.")
                    break
                    
            except Exception as e:
                print(f"[ERROR] {e}")
                break
        
        # Generate session receipt
        self.transcript.generate_receipt(self.private_key)
    
    def start(self):
        """Start the server"""
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)
        print(f"[SERVER] Listening on {self.host}:{self.port}")
        
        while True:
            conn, addr = self.socket.accept()
            print(f"\n[SERVER] New connection from {addr}")
            
            try:
                
                #Phase 1: Certificate exchange
                client_cert, client_pk = self.handle_certificate_exchange(conn)
                if not client_cert:
                    conn.close()
                    continue
                
                # Phase 2: Auth DH
                auth_key = self.handle_auth_dh(conn)
                
                # Phase 3: Registration/Login
                if not self.handle_registration(conn, auth_key):
                    conn.close()
                    continue
                
                # Phase 4: Chat DH
                session_key = self.handle_chat_dh(conn)
                
                # Phase 5: Chat loop
                self.chat_loop(conn, session_key, client_pk, client_cert)
                
            except Exception as e:
                print(f"[ERROR] Connection error: {e}")
            finally:
                conn.close()

if __name__ == "__main__":
    server = SecureServer()
    server.start()
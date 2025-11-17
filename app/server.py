#!/usr/bin/env python3
"""
Secure Chat Server
Implements CIANR protocol for secure communication
"""

import sys
import os

# Fix import path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

import socket
import json
import base64
import time
import hashlib
from dotenv import load_dotenv

from crypto.aes import AESCipher
from crypto.dh import DiffieHellman
from crypto.pki import PKIValidator
from crypto.sign import DigitalSignature
from storage.db import DatabaseManager
from storage.transcript import TranscriptManager

# Load environment variables
load_dotenv()

class SecureServer:
    def __init__(self, host=None, port=None):
        self.host = host or os.getenv("SERVER_HOST", "localhost")
        self.port = int(port or os.getenv("SERVER_PORT", 8888))
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.db = DatabaseManager()
        self.transcript = TranscriptManager("server")
        self.session_key = None
        self.client_public_key = None
        self.seqno_received = 0
        self.load_credentials()
        
    def load_credentials(self):
        """Load server certificate and private key"""
        try:
            cert_path = os.getenv("SERVER_CERT", "certs/server_cert.pem")
            key_path = os.getenv("SERVER_KEY", "certs/server_private.pem")
            ca_path = os.getenv("CA_CERT", "certs/ca_cert.pem")
            
            with open(cert_path, "r") as f:
                self.cert_pem = f.read()
            
            with open(key_path, "rb") as f:
                from cryptography.hazmat.primitives import serialization
                self.private_key = serialization.load_pem_private_key(
                    f.read(), 
                    password=None
                )
            
            with open(ca_path, "r") as f:
                self.ca_cert_pem = f.read()
                
            print("[SERVER] ✓ Credentials loaded successfully")
        except FileNotFoundError as e:
            print(f"[ERROR] Certificate files not found: {e}")
            print("Please run: python scripts/gen_ca.py and python scripts/gen_cert.py")
            exit(1)
    
    def handle_certificate_exchange(self, conn):
        """Phase 1: Certificate exchange and validation"""
        print("\n[PHASE 1] Certificate Exchange...")
        
        # Receive client hello
        client_hello = json.loads(conn.recv(4096).decode())
        client_cert_pem = client_hello['client_cert']
        print("[SERVER] ← Received client certificate")
        
        # Validate client certificate
        is_valid, msg = PKIValidator.verify_certificate(
            client_cert_pem, 
            self.ca_cert_pem
        )
        
        if not is_valid:
            error = {"type": "error", "msg": msg}
            conn.send(json.dumps(error).encode())
            print(f"[SERVER] ✗ {msg}")
            return None, None
        
        print(f"[SERVER] ✓ Client certificate validated: {msg}")
        
        # Send server hello
        server_hello = {
            "type": "server_hello",
            "server_cert": self.cert_pem,
            "nonce": base64.b64encode(os.urandom(16)).decode()
        }
        conn.send(json.dumps(server_hello).encode())
        print("[SERVER] → Sent server certificate")
        
        # Extract client public key
        self.client_public_key = PKIValidator.extract_public_key(client_cert_pem)
        
        return client_cert_pem, self.client_public_key
    
    def handle_auth_dh(self, conn):
        """Phase 2: DH key exchange for authentication"""
        print("\n[PHASE 2] Authentication Key Exchange (DH)...")
        
        # Receive client DH parameters
        dh_client = json.loads(conn.recv(4096).decode())
        p = dh_client['p']
        g = dh_client['g']
        A = dh_client['A']
        print("[SERVER] ← Received client DH parameters")
        
        # Generate server DH keys
        dh = DiffieHellman(p, g)
        dh.generate_private_key()
        B = dh.generate_public_key()
        
        # Send server DH public key
        dh_server = {"type": "dh_server", "B": B}
        conn.send(json.dumps(dh_server).encode())
        print("[SERVER] → Sent server DH public key")
        
        # Compute shared secret and derive AES key
        shared_secret = dh.compute_shared_secret(A)
        auth_key = DiffieHellman.derive_aes_key(shared_secret)
        print("[SERVER] ✓ Derived authentication key")
        
        return auth_key
    
    def handle_registration(self, conn, auth_key):
        """Phase 3: Handle registration or login"""
        print("\n[PHASE 3] Authentication...")
        
        # Receive encrypted auth message
        auth_msg = json.loads(conn.recv(4096).decode())
        encrypted_data = base64.b64decode(auth_msg['data'])
        print("[SERVER] ← Received encrypted authentication data")
        
        # Decrypt using auth key
        decrypted = AESCipher.decrypt(encrypted_data, auth_key)
        auth_data = json.loads(decrypted.decode())
        
        if auth_data['type'] == 'register':
            print("[SERVER] Processing registration...")
            success = self.db.register_user(
                auth_data['email'],
                auth_data['username'],
                auth_data['pwd']
            )
            response = {
                "type": "register_response", 
                "success": success,
                "msg": "Registration successful" if success else "User already exists"
            }
        
        elif auth_data['type'] == 'login':
            print("[SERVER] Processing login...")
            success = self.db.verify_login(
                auth_data['email'],
                auth_data['pwd']
            )
            response = {
                "type": "login_response",
                "success": success,
                "msg": "Login successful" if success else "Invalid credentials"
            }
        else:
            response = {"type": "error", "success": False, "msg": "Invalid request"}
        
        # Encrypt response
        encrypted_response = AESCipher.encrypt(
            json.dumps(response).encode(),
            auth_key
        )
        conn.send(base64.b64encode(encrypted_response))
        print(f"[SERVER] → Sent response: {response['msg']}")
        
        return response['success']
    
    def handle_login(self, email, pwd_hash_from_client):
        """Verify login credentials"""
        try:
            cursor = self.db.conn.cursor()
            
            # Retrieve stored salt and password hash
            cursor.execute(
                "SELECT salt, pwd_hash FROM users WHERE email = %s",
                (email,)
            )
            result = cursor.fetchone()
            
            if not result:
                return {"success": False, "msg": "User not found"}
            
            stored_salt, stored_pwd_hash = result
            
            # CRITICAL: Client must send password, not hash
            # Server recomputes hash with stored salt
            
            # If client sends plain password:
            computed_hash = hashlib.sha256(stored_salt + pwd_hash_from_client.encode()).hexdigest()
            
            if computed_hash == stored_pwd_hash:
                return {"success": True, "msg": "Login successful"}
            else:
                return {"success": False, "msg": "Invalid password"}
                
        except Exception as e:
            print(f"[DB] Login error: {e}")
            return {"success": False, "msg": "Login failed"}
    
    def handle_chat_dh(self, conn):
        """Phase 4: DH key exchange for chat session"""
        print("\n[PHASE 4] Chat Session Key Exchange...")
        
        # New DH exchange for chat
        dh_client = json.loads(conn.recv(4096).decode())
        p = dh_client['p']
        g = dh_client['g']
        A = dh_client['A']
        print("[SERVER] ← Received chat DH parameters")
        
        dh = DiffieHellman(p, g)
        dh.generate_private_key()
        B = dh.generate_public_key()
        
        dh_server = {"type": "dh_server", "B": B}
        conn.send(json.dumps(dh_server).encode())
        print("[SERVER] → Sent chat DH public key")
        
        shared_secret = dh.compute_shared_secret(A)
        self.session_key = DiffieHellman.derive_aes_key(shared_secret)
        print("[SERVER] ✓ Derived chat session key")
        
        return self.session_key
    
    def chat_loop(self, conn, client_cert_pem):
        """Phase 5: Encrypted chat with integrity checks"""
        print("\n[PHASE 5] Chat Session Started")
        print("="*50)
        
        cert_fingerprint = PKIValidator.get_certificate_fingerprint(client_cert_pem)
        
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
                    if seqno <= self.seqno_received:
                        print(f"\n[SECURITY] REPLAY ATTACK: seqno={seqno} (expected >{self.seqno_received})")
                        continue
                    
                    # Verify signature
                    if not DigitalSignature.verify_message(
                        self.client_public_key, sig, seqno, ts, ct
                    ):
                        print(f"\n[SECURITY] SIG_FAIL: Invalid signature on message {seqno}")
                        continue
                    
                    # Decrypt message
                    plaintext = AESCipher.decrypt(ct, self.session_key)
                    print(f"\n[CLIENT]: {plaintext.decode()}")
                    
                    # Update sequence
                    self.seqno_received = seqno
                    
                    # Log to transcript
                    self.transcript.add_entry(
                        seqno, ts, ct, sig, cert_fingerprint
                    )
                
                elif msg['type'] == 'close':
                    print("\n[SERVER] Client requested disconnect")
                    break
                    
            except Exception as e:
                print(f"\n[ERROR] Chat error: {e}")
                import traceback
                traceback.print_exc()
                break
        
        # Generate session receipt
        print("\n[SERVER] Generating session receipt...")
        self.transcript.generate_receipt(self.private_key)
    
    def start(self):
        """Start the server"""
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)
        print("\n" + "="*50)
        print("SECURECHAT SERVER v1.0")
        print("="*50)
        print(f"[SERVER] Listening on {self.host}:{self.port}")
        print("Waiting for connections...\n")
        
        while True:
            conn, addr = self.socket.accept()
            print(f"\n[SERVER] New connection from {addr}")
            
            try:
                # Phase 1: Certificate exchange
                client_cert, client_pk = self.handle_certificate_exchange(conn)
                if not client_cert:
                    conn.close()
                    continue
                
                # Phase 2: Auth DH
                auth_key = self.handle_auth_dh(conn)
                
                # Phase 3: Registration/Login
                if not self.handle_registration(conn, auth_key):
                    conn.close()
                    print("[SERVER] Authentication failed, closing connection\n")
                    continue
                
                # Phase 4: Chat DH
                self.handle_chat_dh(conn)
                
                # Phase 5: Chat loop
                self.chat_loop(conn, client_cert)
                
            except Exception as e:
                print(f"\n[ERROR] Connection error: {e}")
                import traceback
                traceback.print_exc()
            finally:
                conn.close()
                print("\n[SERVER] Connection closed. Ready for new connections...\n")


if __name__ == "__main__":
    server = SecureServer()
    server.start()
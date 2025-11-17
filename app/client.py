"""
Secure Chat Client
Implements CIANR protocol for secure communication
"""

import socket
import json
import base64
import os
import time
import hashlib
import threading
from getpass import getpass

from crypto.aes import AESCipher
from crypto.dh import DiffieHellman
from crypto.pki import PKIValidator
from crypto.sign import DigitalSignature
from storage.transcript import TranscriptManager

class SecureClient:
    def __init__(self, host='localhost', port=8888):
        self.host = host
        self.port = port
        self.socket = None
        self.transcript = TranscriptManager("client")
        self.session_key = None
        self.server_public_key = None
        self.seqno = 0
        self.seqno_received = 0
        self.load_credentials()
        
    def load_credentials(self):
        """Load client certificate and private key"""
        try:
            with open("certs/client_cert.pem", "r") as f:
                self.cert_pem = f.read()
            
            with open("certs/client_private.pem", "rb") as f:
                from cryptography.hazmat.primitives import serialization
                self.private_key = serialization.load_pem_private_key(
                    f.read(), 
                    password=None
                )
            
            with open("certs/ca_cert.pem", "r") as f:
                self.ca_cert_pem = f.read()
                
            print("[CLIENT] ✓ Credentials loaded successfully")
        except FileNotFoundError as e:
            print(f"[ERROR] Certificate files not found: {e}")
            print("Please run: python scripts/gen_ca.py and python scripts/gen_cert.py")
            exit(1)
    
    def connect(self):
        """Establish TCP connection to server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            print(f"[CLIENT] ✓ Connected to {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"[ERROR] Connection failed: {e}")
            return False
    
    def certificate_exchange(self):
        """
        Phase 1: Certificate Exchange and Validation
        
        Key Difference from Server:
        - Client INITIATES the exchange by sending hello first
        - Client RECEIVES server certificate and validates it
        """
        print("\n[PHASE 1] Certificate Exchange...")
        
        # CLIENT SENDS FIRST (different from server which receives first)
        client_hello = {
            "type": "hello",
            "client_cert": self.cert_pem,
            "nonce": base64.b64encode(os.urandom(16)).decode()
        }
        self.socket.send(json.dumps(client_hello).encode())
        print("[CLIENT] → Sent client certificate")
        
        # Receive server hello
        server_hello = json.loads(self.socket.recv(4096).decode())
        
        if server_hello.get('type') == 'error':
            print(f"[ERROR] Server rejected connection: {server_hello['msg']}")
            return False
        
        server_cert_pem = server_hello['server_cert']
        print("[CLIENT] ← Received server certificate")
        
        # Validate server certificate
        is_valid, msg = PKIValidator.verify_certificate(
            server_cert_pem,
            self.ca_cert_pem
        )
        
        if not is_valid:
            print(f"[ERROR] {msg}")
            return False
        
        print(f"[CLIENT] ✓ Server certificate validated: {msg}")
        
        # Extract server public key for signature verification
        self.server_public_key = PKIValidator.extract_public_key(server_cert_pem)
        self.server_cert_pem = server_cert_pem
        
        return True
    
    def auth_key_exchange(self):
        """
        Phase 2: DH Key Exchange for Authentication
        
        Key Difference from Server:
        - Client GENERATES and SENDS DH parameters (p, g)
        - Server only receives and responds
        """
        print("\n[PHASE 2] Authentication Key Exchange (DH)...")
        
        # CLIENT GENERATES DH PARAMETERS (server uses client's parameters)
        dh = DiffieHellman()
        dh.generate_private_key()
        A = dh.generate_public_key()
        
        # Send DH parameters to server
        dh_client = {
            "type": "dh_client",
            "p": dh.p,
            "g": dh.g,
            "A": A
        }
        self.socket.send(json.dumps(dh_client).encode())
        print("[CLIENT] → Sent DH parameters (p, g, A)")
        
        # Receive server's public key
        dh_server = json.loads(self.socket.recv(4096).decode())
        B = dh_server['B']
        print("[CLIENT] ← Received server's DH public key (B)")
        
        # Compute shared secret and derive AES key
        shared_secret = dh.compute_shared_secret(B)
        auth_key = DiffieHellman.derive_aes_key(shared_secret)
        print("[CLIENT] ✓ Derived authentication key")
        
        return auth_key
    
    def register(self, auth_key):
        """
        Phase 3a: User Registration
        
        Key Difference from Server:
        - Client COLLECTS user input (email, username, password)
        - Client ENCRYPTS credentials before sending
        - Server only receives and stores
        """
        print("\n[PHASE 3] Registration...")
        
        email = input("Enter email: ").strip()
        username = input("Enter username: ").strip()
        password = getpass("Enter password: ")
        
        # Generate random salt (CLIENT SIDE)
        salt = os.urandom(16)
        
        # Compute salted password hash
        pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
        
        # Prepare registration data
        register_data = {
            "type": "register",
            "email": email,
            "username": username,
            "pwd": pwd_hash,
            "salt": base64.b64encode(salt).decode()
        }
        
        # Encrypt with auth key
        encrypted_data = AESCipher.encrypt(
            json.dumps(register_data).encode(),
            auth_key
        )
        
        # Send encrypted registration
        auth_msg = {
            "type": "auth",
            "data": base64.b64encode(encrypted_data).decode()
        }
        self.socket.send(json.dumps(auth_msg).encode())
        print("[CLIENT] → Sent encrypted registration data")
        
        # Receive response
        response_encrypted = base64.b64decode(self.socket.recv(4096))
        response_decrypted = AESCipher.decrypt(response_encrypted, auth_key)
        response = json.loads(response_decrypted.decode())
        
        if response['success']:
            print(f"[CLIENT] ✓ {response['msg']}")
            return True
        else:
            print(f"[CLIENT] ✗ {response['msg']}")
            return False
    
    def login(self):
        """
        Phase 3b: User Login
        
        Key Difference from Server:
        - Client prompts for credentials
        - Client computes hash with stored salt
        - Server only verifies
        """
        print("\n[PHASE 3] Login...")
        
        email = input("Enter email: ").strip()
        password = getpass("Enter password: ")
        
        # Send PLAIN password (encrypted via AES with auth_key)
        # Server will retrieve salt and hash
        auth_data = {
            "type": "login",
            "email": email,
            "pwd": password  # Send plain password, NOT hashed
        }
        
        encrypted = self.auth_aes.encrypt(json.dumps(auth_data).encode())
        self.sock.sendall(encrypted)
        
        # Receive response
        response_encrypted = base64.b64decode(self.socket.recv(4096))
        response_decrypted = AESCipher.decrypt(response_encrypted, auth_key)
        response = json.loads(response_decrypted.decode())
        
        if response['success']:
            print(f"[CLIENT] ✓ {response['msg']}")
            return True
        else:
            print(f"[CLIENT] ✗ {response['msg']}")
            return False
    
    def chat_key_exchange(self):
        """
        Phase 4: DH Key Exchange for Chat Session
        
        Key Difference from Server:
        - NEW DH exchange (different from auth DH)
        - This key is ONLY for encrypting chat messages
        """
        print("\n[PHASE 4] Chat Session Key Exchange...")
        
        # New DH exchange for chat
        dh = DiffieHellman()
        dh.generate_private_key()
        A = dh.generate_public_key()
        
        dh_client = {
            "type": "dh_client",
            "p": dh.p,
            "g": dh.g,
            "A": A
        }
        self.socket.send(json.dumps(dh_client).encode())
        print("[CLIENT] → Sent chat session DH parameters")
        
        dh_server = json.loads(self.socket.recv(4096).decode())
        B = dh_server['B']
        print("[CLIENT] ← Received server's chat DH public key")
        
        shared_secret = dh.compute_shared_secret(B)
        self.session_key = DiffieHellman.derive_aes_key(shared_secret)
        print("[CLIENT] ✓ Derived chat session key")
        
        return True
    
    def send_message(self, plaintext):
        """
        Phase 5: Send Encrypted and Signed Message
        
        Key Difference from Server:
        - Client creates and sends messages
        - Server receives and verifies
        
        Message Flow:
        1. Increment sequence number
        2. Encrypt plaintext with AES session key
        3. Compute digest: SHA256(seqno || timestamp || ciphertext)
        4. Sign digest with RSA private key
        5. Send: {seqno, timestamp, ciphertext, signature}
        """
        self.seqno += 1
        timestamp = int(time.time() * 1000)
        
        # Encrypt message
        ciphertext = AESCipher.encrypt(plaintext.encode(), self.session_key)
        
        # Sign message
        signature = DigitalSignature.sign_message(
            self.private_key,
            self.seqno,
            timestamp,
            ciphertext
        )
        
        # Prepare message
        msg = {
            "type": "msg",
            "seqno": self.seqno,
            "ts": timestamp,
            "ct": base64.b64encode(ciphertext).decode(),
            "sig": base64.b64encode(signature).decode()
        }
        
        # Send
        self.socket.send(json.dumps(msg).encode())
        
        # Log to transcript
        cert_fingerprint = PKIValidator.get_certificate_fingerprint(self.server_cert_pem)
        self.transcript.add_entry(
            self.seqno,
            timestamp,
            ciphertext,
            signature,
            cert_fingerprint
        )
        
        print(f"[YOU]: {plaintext}")
    
    def send_encrypted_message(self, plaintext):
        # Encrypt
        ciphertext = self.aes.encrypt(plaintext)
        
        # Prepare signed message
        self.seqno += 1
        timestamp = int(time.time() * 1000)  # unix milliseconds
        
        # Compute digest: SHA-256(seqno || timestamp || ciphertext)
        digest_input = f"{self.seqno}||{timestamp}||{ciphertext}".encode()
        digest = hashlib.sha256(digest_input).digest()
        
        # Sign the digest
        signer = DigitalSignature(self.private_key)
        signature = signer.sign(digest)
        
        # Send message with signature
        msg = {
            "type": "msg",
            "seqno": self.seqno,
            "ts": timestamp,
            "ct": base64.b64encode(ciphertext).decode(),
            "sig": base64.b64encode(signature).decode()
        }
        self.sock.sendall(json.dumps(msg).encode() + b'\n')
        
        # Log to transcript
        self.transcript.append(f"{self.seqno}|{timestamp}|{msg['ct']}|{msg['sig']}|{self.server_cert_fingerprint}")
    
    def receive_messages(self):
        """
        Background thread to receive messages from server
        
        Key Difference from Server:
        - Client runs this in a separate thread
        - Server runs in main loop
        """
        while True:
            try:
                data = self.socket.recv(4096)
                if not data:
                    print("\n[CLIENT] Connection closed by server")
                    break
                
                msg = json.loads(data.decode())
                
                if msg['type'] == 'msg':
                    seqno = msg['seqno']
                    ts = msg['ts']
                    ct = base64.b64decode(msg['ct'])
                    sig = base64.b64decode(msg['sig'])
                    
                    # Replay protection
                    if seqno <= self.seqno_received:
                        print(f"\n[SECURITY] REPLAY: Received old seqno {seqno}")
                        continue
                    
                    # Verify signature
                    if not DigitalSignature.verify_message(
                        self.server_public_key, sig, seqno, ts, ct
                    ):
                        print(f"\n[SECURITY] SIG_FAIL: Invalid signature on message {seqno}")
                        continue
                    
                    # Decrypt
                    plaintext = AESCipher.decrypt(ct, self.session_key)
                    print(f"\n[SERVER]: {plaintext.decode()}")
                    print("[YOU]: ", end='', flush=True)  # Restore prompt
                    
                    # Update sequence
                    self.seqno_received = seqno
                    
                    # Log to transcript
                    cert_fingerprint = PKIValidator.get_certificate_fingerprint(self.server_cert_pem)
                    self.transcript.add_entry(seqno, ts, ct, sig, cert_fingerprint)
                    
            except Exception as e:
                print(f"\n[ERROR] Receive error: {e}")
                break
    
    def chat(self):
        """
        Phase 5: Interactive Chat Loop
        
        Key Difference from Server:
        - Client has user input loop
        - Client runs receiver in background thread
        """
        print("\n" + "="*50)
        print("SECURE CHAT SESSION STARTED")
        print("Type your messages (or 'quit' to exit)")
        print("="*50 + "\n")
        
        # Start background thread to receive messages
        receiver_thread = threading.Thread(target=self.receive_messages, daemon=True)
        receiver_thread.start()
        
        # Main input loop
        while True:
            try:
                message = input("[YOU]: ")
                
                if message.lower() in ['quit', 'exit', 'q']:
                    # Send close message
                    close_msg = {"type": "close"}
                    self.socket.send(json.dumps(close_msg).encode())
                    break
                
                if message.strip():
                    self.send_message(message)
                    
            except KeyboardInterrupt:
                print("\n[CLIENT] Interrupted by user")
                break
            except Exception as e:
                print(f"\n[ERROR] {e}")
                break
        
        # Generate session receipt
        print("\n[CLIENT] Generating session receipt...")
        self.transcript.generate_receipt(self.private_key)
        print("[CLIENT] ✓ Session closed")
    
    def generate_session_receipt(self):
        """Generate signed receipt of conversation"""
        # Compute transcript hash
        transcript_data = '\n'.join(self.transcript).encode()
        transcript_hash = hashlib.sha256(transcript_data).hexdigest()
        
        # Sign the hash
        signer = DigitalSignature(self.private_key)
        signature = signer.sign(transcript_hash.encode())
        
        receipt = {
            "type": "receipt",
            "peer": "client",
            "first_seq": 1,
            "last_seq": self.seqno,
            "transcript_sha256": transcript_hash,
            "sig": base64.b64encode(signature).decode()
        }
        
        # Save transcript and receipt
        with open(f"transcripts/client_session_{int(time.time())}.txt", 'w') as f:
            f.write('\n'.join(self.transcript))
        
        with open(f"transcripts/client_receipt_{int(time.time())}.json", 'w') as f:
            json.dump(receipt, f, indent=2)
        
        print(f"\n[CLIENT] ✓ Session receipt generated: {transcript_hash}")
        return receipt
    
    def start(self):
        """
        Main client flow
        
        Complete Protocol Flow (CLIENT PERSPECTIVE):
        1. Connect to server
        2. Exchange certificates (client sends first)
        3. DH key exchange for auth
        4. Register or Login
        5. DH key exchange for chat
        6. Chat loop
        7. Generate receipt on exit
        """
        print("\n" + "="*50)
        print("SECURECHAT CLIENT v1.0")
        print("="*50)
        
        # Step 1: Connect
        if not self.connect():
            return
        
        # Step 2: Certificate exchange
        if not self.certificate_exchange():
            self.socket.close()
            return
        
        # Step 3: Auth DH
        auth_key = self.auth_key_exchange()
        
        # Step 4: Register or Login
        choice = input("\n[1] Register\n[2] Login\nChoice: ").strip()
        
        if choice == '1':
            success = self.register(auth_key)
        elif choice == '2':
            success = self.login(auth_key)
        else:
            print("[ERROR] Invalid choice")
            self.socket.close()
            return
        
        if not success:
            self.socket.close()
            return
        
        # Step 5: Chat session DH
        if not self.chat_key_exchange():
            self.socket.close()
            return
        
        # Step 6: Chat
        self.chat()
        
        # Cleanup
        self.socket.close()


if __name__ == "__main__":
    client = SecureClient()
    client.start()
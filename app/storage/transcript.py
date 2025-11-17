"""
Transcript and Session Receipt Management
"""

import hashlib
import json
import base64
from crypto.sign import DigitalSignature

class TranscriptManager:
    def __init__(self, peer_type):
        self.peer_type = peer_type  # "client" or "server"
        self.entries = []
        self.first_seq = None
        self.last_seq = None
    
    def add_entry(self, seqno, timestamp, ciphertext, signature, peer_cert_fingerprint):
        """Add message to transcript"""
        if self.first_seq is None:
            self.first_seq = seqno
        self.last_seq = seqno
        
        entry = {
            "seqno": seqno,
            "timestamp": timestamp,
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "signature": base64.b64encode(signature).decode(),
            "peer_cert_fingerprint": peer_cert_fingerprint
        }
        self.entries.append(entry)
    
    def compute_transcript_hash(self):
        """Compute SHA-256 hash of entire transcript"""
        # Concatenate all entries
        transcript_lines = []
        for entry in self.entries:
            line = f"{entry['seqno']}|{entry['timestamp']}|{entry['ciphertext']}|{entry['signature']}|{entry['peer_cert_fingerprint']}"
            transcript_lines.append(line)
        
        transcript_data = "\n".join(transcript_lines).encode()
        return hashlib.sha256(transcript_data).hexdigest()
    
    def generate_receipt(self, private_key):
        """Generate signed session receipt"""
        if not self.entries:
            print(f"[{self.peer_type.upper()}] No messages to create receipt")
            return
        
        # Compute transcript hash
        transcript_hash = self.compute_transcript_hash()
        
        # Sign the hash
        signature = DigitalSignature.sign(private_key, transcript_hash.encode())
        
        # Create receipt
        receipt = {
            "type": "receipt",
            "peer": self.peer_type,
            "first_seq": self.first_seq,
            "last_seq": self.last_seq,
            "transcript_sha256": transcript_hash,
            "sig": base64.b64encode(signature).decode()
        }
        
        # Save receipt
        with open(f"logs/{self.peer_type}_receipt.json", "w") as f:
            json.dump(receipt, f, indent=2)
        
        # Save full transcript
        with open(f"logs/{self.peer_type}_transcript.json", "w") as f:
            json.dump(self.entries, f, indent=2)
        
        print(f"[{self.peer_type.upper()}] Receipt saved: logs/{self.peer_type}_receipt.json")
        print(f"[{self.peer_type.upper()}] Transcript saved: logs/{self.peer_type}_transcript.json")
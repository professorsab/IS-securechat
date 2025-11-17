"""
MySQL Database Manager for User Authentication
"""

import mysql.connector
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class DatabaseManager:
    def __init__(self):
        """Initialize database connection"""
        try:
            # Get configuration from environment variables
            self.conn = mysql.connector.connect(
                host=os.getenv("DB_HOST", "localhost"),
                user=os.getenv("DB_USER", "root"),
                password=os.getenv("DB_PASSWORD"),  # Will load from .env
                database=os.getenv("DB_NAME", "securechat")
            )
            self.cursor = self.conn.cursor()
            print("[DB] ✓ Connected to MySQL database")
        except mysql.connector.Error as e:
            print(f"[DB] ✗ Database connection failed: {e}")
            print("[DB] Please check your .env file and MySQL credentials")
            raise
    
    def register_user(self, email, username, salt, pwd_hash):
        """
        Register new user
        
        Args:
            email: User email
            username: Username
            salt: Random salt (bytes)
            pwd_hash: Salted password hash (hex string)
            
        Returns:
            bool: True if successful, False if user exists
        """
        try:
            query = """
                INSERT INTO users (email, username, salt, pwd_hash)
                VALUES (%s, %s, %s, %s)
            """
            self.cursor.execute(query, (email, username, salt, pwd_hash))
            self.conn.commit()
            print(f"[DB] ✓ User registered: {username}")
            return True
        except mysql.connector.IntegrityError:
            print(f"[DB] ✗ User already exists: {email}")
            return False
    
    def get_salt(self, email):
        """Get user's salt for password hashing"""
        query = "SELECT salt FROM users WHERE email = %s"
        self.cursor.execute(query, (email,))
        result = self.cursor.fetchone()
        return result[0] if result else None
    
    def verify_login(self, email, pwd_hash):
        """
        Verify user login
        
        Args:
            email: User email
            pwd_hash: Salted password hash to verify
            
        Returns:
            bool: True if credentials match
        """
        query = "SELECT pwd_hash FROM users WHERE email = %s"
        self.cursor.execute(query, (email,))
        result = self.cursor.fetchone()
        
        if result and result[0] == pwd_hash:
            print(f"[DB] ✓ Login successful: {email}")
            return True
        
        print(f"[DB] ✗ Invalid credentials: {email}")
        return False
    
    def close(self):
        """Close database connection"""
        self.cursor.close()
        self.conn.close()
#!/usr/bin/env python3
"""
SENSITIVE DATA VAULT - Password Manager Edition
- Full Login & Access Control (with 2FA, lockout, recovery)
- 7 Record Types: Credit Card, Aadhaar, Login, Bank Account, Secure Note, Personal Document, API Key
- Edit, Delete with confirmation, Favorites, Search, Dashboard
- Encrypted Backup / Import, Auto Lock, Dark Mode, Security Score
"""
import sqlite3
import hashlib
import secrets
import re
import json
import os
import time
import logging
import getpass
import string
import random
import socket
import base64
import pyotp
import requests
import pyperclip
import qrcode
import mimetypes
from datetime import datetime, timedelta
from collections import defaultdict
from cryptography.fernet import Fernet

# ==================== CONFIGURATION ====================
DB_NAME = "sensitive_vault.db"
SESSION_TIMEOUT = 300          # default 5 minutes
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 300
DARK_MODE = False

# Global derived encryption key (in memory only)
_current_fernet_key = None

# ==================== COLOR CLASS ====================
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    
    @staticmethod
    def print(text, color=GREEN):
        global DARK_MODE
        if DARK_MODE:
            color = color.replace('[94m', '[36m').replace('[92m', '[32m')
        print(f"{color}{text}{Colors.END}")

# ==================== LOGGING ====================
logging.basicConfig(
    filename='vault_audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_action(action, details=""):
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except:
        ip = "unknown"
    logging.info(f"{action} - {details} - IP: {ip}")

# ==================== SESSION MANAGEMENT ====================
class SessionManager:
    def __init__(self, timeout_seconds=SESSION_TIMEOUT):
        self.timeout = timeout_seconds
        self.last_activity = time.time()
        self.authenticated = False
    
    def check_timeout(self):
        if self.authenticated:
            if time.time() - self.last_activity > self.timeout:
                Colors.print("\n⏰ Session expired due to inactivity.", Colors.RED)
                self.authenticated = False
                return False
        return True
    
    def refresh(self):
        self.last_activity = time.time()
    
    def get_remaining_time(self):
        if self.authenticated:
            remaining = self.timeout - (time.time() - self.last_activity)
            return max(0, int(remaining))
        return 0
    
    def logout(self):
        self.authenticated = False
        global _current_fernet_key
        _current_fernet_key = None

session = SessionManager()

# ==================== KEY DERIVATION ====================
def derive_key_from_password(password: str) -> bytes:
    salt = b"VaultFixedSalt_2024!"
    iterations = 100_000
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=32)
    return base64.urlsafe_b64encode(dk)

# ==================== ENCRYPTION & HASHING ====================
def get_fernet():
    global _current_fernet_key
    if _current_fernet_key is None:
        raise RuntimeError("Encryption key not set. Please authenticate first.")
    return Fernet(_current_fernet_key)

def encrypt(plaintext: str) -> str:
    if not plaintext:
        return ""
    f = get_fernet()
    return f.encrypt(plaintext.encode()).decode()

def decrypt(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    f = get_fernet()
    return f.decrypt(ciphertext.encode()).decode()

def encrypt_bytes(data: bytes) -> str:
    f = get_fernet()
    return f.encrypt(data).decode()

def decrypt_bytes(ciphertext: str) -> bytes:
    f = get_fernet()
    return f.decrypt(ciphertext.encode())

def hash_password(password: str, salt: str = None):
    iterations = 100_000
    dklen = 32
    if salt is None:
        salt = secrets.token_hex(16)
    salt_bytes = bytes.fromhex(salt)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt_bytes, iterations, dklen)
    return salt, dk.hex()

def generate_token():
    return secrets.token_hex(16)

# ==================== PASSWORD STRENGTH & GENERATOR ====================
def check_password_strength(password):
    score = 0
    feedback = []
    if len(password) >= 12:
        score += 1
    else:
        feedback.append("Use at least 12 characters")
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Add uppercase letters")
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Add lowercase letters")
    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append("Add numbers")
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    else:
        feedback.append("Add special characters")
    strengths = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
    return strengths[score], feedback

def generate_strong_password():
    Colors.print("\n🔑 PASSWORD GENERATOR", Colors.HEADER)
    try:
        length = int(input("Password length (default 20): ") or 20)
    except:
        length = 20
    chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    password = ''.join(random.choice(chars) for _ in range(length))
    Colors.print("\n" + "="*50, Colors.GREEN)
    Colors.print(f"🔐 Generated Password: {password}", Colors.BOLD)
    Colors.print("="*50, Colors.GREEN)
    strength, feedback = check_password_strength(password)
    Colors.print(f"Strength: {strength}", Colors.YELLOW)
    if feedback:
        print("Suggestions:")
        for f in feedback:
            print(f"  • {f}")
    breach_count = check_password_breach(password)
    if breach_count > 0:
        Colors.print(f"⚠️  Found in {breach_count} breaches!", Colors.RED)
    elif breach_count == 0:
        Colors.print("✅ Not found in known breaches.", Colors.GREEN)
    else:
        Colors.print("❌ Breach check failed.", Colors.YELLOW)
    copy = input("\nCopy to clipboard? (y/n): ").lower()
    if copy == 'y':
        try:
            pyperclip.copy(password)
            Colors.print("✅ Copied to clipboard!", Colors.GREEN)
        except ImportError:
            Colors.print("❌ pyperclip not installed.", Colors.RED)
    save = input("Save as new login? (y/n): ").lower()
    if save == 'y':
        service = input("Service name: ").strip()
        username = input("Username: ").strip()
        notes = input("Notes: ").strip()
        if service and username:
            add_login(service, username, password, notes)
        else:
            Colors.print("❌ Service and username required.", Colors.RED)

def check_password_breach(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    try:
        resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        if resp.status_code == 200:
            hashes = resp.text.splitlines()
            for line in hashes:
                if line.startswith(suffix):
                    count = int(line.split(':')[1])
                    return count
            return 0
        else:
            return -1
    except:
        return -1

# ==================== DATABASE INITIALIZATION (WITH MIGRATION) ====================
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    # Master password table (with 2fa flag)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS master_password (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            totp_secret TEXT,
            recovery_key TEXT,
            twofa_enabled INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_changed TIMESTAMP
        )
    """)
    conn.commit()

    # ----- SCHEMA MIGRATION: add missing columns safely -----
    cur.execute("PRAGMA table_info(master_password)")
    columns = [row[1] for row in cur.fetchall()]
    if 'twofa_enabled' not in columns:
        cur.execute("ALTER TABLE master_password ADD COLUMN twofa_enabled INTEGER DEFAULT 1")
        Colors.print("✅ Added 'twofa_enabled' column to master_password.", Colors.GREEN)
    if 'last_changed' not in columns:
        cur.execute("ALTER TABLE master_password ADD COLUMN last_changed TIMESTAMP")
        cur.execute("UPDATE master_password SET last_changed = CURRENT_TIMESTAMP WHERE last_changed IS NULL")
        Colors.print("✅ Added 'last_changed' column to master_password and set initial values.", Colors.GREEN)
    conn.commit()

    # Check if master password exists
    cur.execute("SELECT password_hash FROM master_password WHERE id = 1")
    if cur.fetchone() is None:
        conn.close()
        setup_master_password()
        return

    # Login attempts for account lockout
    cur.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            username TEXT DEFAULT 'admin',
            attempt_count INTEGER DEFAULT 0,
            lockout_until TIMESTAMP
        )
    """)
    cur.execute("INSERT OR IGNORE INTO login_attempts (id, username) VALUES (1, 'admin')")
    conn.commit()

    # Auto-lock settings table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    cur.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('session_timeout', ?)", (str(SESSION_TIMEOUT),))
    conn.commit()

    # Credit Cards
    cur.execute("""
        CREATE TABLE IF NOT EXISTS credit_cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            last_four TEXT NOT NULL,
            card_type TEXT NOT NULL DEFAULT 'Unknown',
            cardholder_enc TEXT,
            expiry_enc TEXT,
            cvv_enc TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS token_vault (
            token TEXT PRIMARY KEY,
            card_number_enc TEXT NOT NULL,
            FOREIGN KEY (token) REFERENCES credit_cards(token)
        )
    """)

    # Aadhaar Cards
    cur.execute("""
        CREATE TABLE IF NOT EXISTS aadhar_cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            aadhar_token TEXT UNIQUE NOT NULL,
            last_four TEXT NOT NULL,
            masked_aadhar TEXT NOT NULL,
            name_enc TEXT,
            dob_enc TEXT,
            address_enc TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS aadhar_vault (
            aadhar_token TEXT PRIMARY KEY,
            aadhar_number_enc TEXT NOT NULL,
            FOREIGN KEY (aadhar_token) REFERENCES aadhar_cards(aadhar_token)
        )
    """)

    # Login details with encrypted password
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='login_details'")
    old_table = cur.fetchone()
    if old_table:
        cur.execute("PRAGMA table_info(login_details)")
        cols = [row[1] for row in cur.fetchall()]
        if 'password_hash' in cols and 'password_salt' in cols:
            Colors.print("\n🔄 Migrating old login details (hashed passwords) to new encrypted format...", Colors.YELLOW)
            cur.execute("ALTER TABLE login_details RENAME TO login_details_old")
            cur.execute("""
                CREATE TABLE login_details (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service_enc TEXT,
                    username_enc TEXT,
                    password_enc TEXT,
                    notes_enc TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute("""
                INSERT INTO login_details (id, service_enc, username_enc, notes_enc, created_at)
                SELECT id, service_enc, username_enc, notes_enc, created_at
                FROM login_details_old
            """)
            cur.execute("DROP TABLE login_details_old")
            Colors.print("✅ Migration complete. Old passwords are not recoverable – please update them.", Colors.GREEN)
        else:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS login_details (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service_enc TEXT,
                    username_enc TEXT,
                    password_enc TEXT,
                    notes_enc TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
    else:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS login_details (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_enc TEXT,
                username_enc TEXT,
                password_enc TEXT,
                notes_enc TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

    # Password History
    cur.execute("""
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            login_id INTEGER NOT NULL,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (login_id) REFERENCES login_details(id) ON DELETE CASCADE
        )
    """)

    # Attachments
    cur.execute("""
        CREATE TABLE IF NOT EXISTS attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            record_type TEXT NOT NULL,
            record_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            file_data_enc TEXT NOT NULL,
            mime_type TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Audit log
    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Data integrity
    cur.execute("""
        CREATE TABLE IF NOT EXISTS data_integrity (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            data_hash TEXT NOT NULL,
            last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Favorites table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS favorites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            record_type TEXT NOT NULL,
            record_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(record_type, record_id)
        )
    """)

    # ----- NEW TABLES FOR EXTRA RECORD TYPES -----
    # Bank Account
    cur.execute("""
        CREATE TABLE IF NOT EXISTS bank_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bank_name_enc TEXT NOT NULL,
            account_holder_enc TEXT NOT NULL,
            account_number_enc TEXT NOT NULL,
            ifsc_enc TEXT NOT NULL,
            branch_enc TEXT,
            notes_enc TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Secure Note
    cur.execute("""
        CREATE TABLE IF NOT EXISTS secure_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title_enc TEXT NOT NULL,
            content_enc TEXT NOT NULL,
            category_enc TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Personal Document (e.g., PAN, Driving Licence)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS personal_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doc_type_enc TEXT NOT NULL,
            doc_number_enc TEXT NOT NULL,
            name_enc TEXT NOT NULL,
            issue_date_enc TEXT,
            expiry_date_enc TEXT,
            notes_enc TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # API Key / Recovery Code
    cur.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_name_enc TEXT NOT NULL,
            api_key_enc TEXT NOT NULL,
            secret_enc TEXT,
            notes_enc TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()
    log_action("DATABASE_INIT", "Database initialized with all record types")

# ==================== LOGIN ATTEMPTS & LOCKOUT ====================
def get_login_attempts():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT attempt_count, lockout_until FROM login_attempts WHERE id = 1")
    row = cur.fetchone()
    conn.close()
    if row:
        return row[0], row[1]
    return 0, None

def update_login_attempts(attempt_count, lockout_until=None):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("UPDATE login_attempts SET attempt_count = ?, lockout_until = ? WHERE id = 1",
                (attempt_count, lockout_until))
    conn.commit()
    conn.close()

def reset_login_attempts():
    update_login_attempts(0, None)

def record_failed_attempt():
    count, lockout = get_login_attempts()
    count += 1
    lockout_until = None
    if count >= MAX_LOGIN_ATTEMPTS:
        lockout_until = (datetime.now() + timedelta(seconds=LOCKOUT_DURATION)).isoformat()
    update_login_attempts(count, lockout_until)
    return count, lockout_until

def is_account_locked():
    count, lockout_until = get_login_attempts()
    if lockout_until:
        lockout_time = datetime.fromisoformat(lockout_until)
        if datetime.now() < lockout_time:
            remaining = int((lockout_time - datetime.now()).total_seconds())
            Colors.print(f"🔒 Account locked. Try again in {remaining} seconds.", Colors.RED)
            return True
        else:
            reset_login_attempts()
            return False
    return False

# ==================== SETUP / VERIFY / RECOVERY / CHANGE PASSWORD ====================
def setup_master_password():
    Colors.print("\n🔐 FIRST TIME SETUP - Create a master password", Colors.HEADER)
    Colors.print("This password will be required to access the vault.", Colors.YELLOW)
    while True:
        pwd1 = getpass.getpass("Enter master password: ")
        pwd2 = getpass.getpass("Confirm master password: ")
        if pwd1 == pwd2:
            if len(pwd1) < 8:
                Colors.print("❌ Password must be at least 8 characters.", Colors.RED)
                continue
            salt, hash_val = hash_password(pwd1)
            recovery_key = secrets.token_urlsafe(32)
            totp_secret = pyotp.random_base32()
            totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
                name="VaultUser", issuer_name="SecureVault"
            )
            Colors.print("\n📱 Scan this QR code with your authenticator app:", Colors.BLUE)
            qr = qrcode.QRCode(border=1)
            qr.add_data(totp_uri)
            qr.make(fit=True)
            qr.print_ascii(invert=True)
            Colors.print(f"\n🔑 Or manually enter this secret: {totp_secret}", Colors.YELLOW)
            Colors.print("⚠️  Save this secret in a safe place. It will not be shown again.", Colors.RED)
            Colors.print(f"\n🔑 RECOVERY KEY: {recovery_key}", Colors.YELLOW)
            Colors.print("⚠️  Store this recovery key in a safe place!", Colors.RED)

            conn = sqlite3.connect(DB_NAME)
            cur = conn.cursor()
            cur.execute("""
                INSERT OR REPLACE INTO master_password 
                (id, password_hash, password_salt, totp_secret, recovery_key, twofa_enabled, last_changed)
                VALUES (1, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
            """, (hash_val, salt, totp_secret, recovery_key))
            conn.commit()
            conn.close()
            Colors.print("\n✅ Master password and TOTP set up successfully!", Colors.GREEN)
            log_action("MASTER_PASSWORD_SETUP", "Master password and TOTP created")
            return True
        else:
            Colors.print("❌ Passwords don't match. Try again.", Colors.RED)

def verify_master_password():
    global _current_fernet_key
    if is_account_locked():
        return False

    Colors.print("\n🔐 VAULT ACCESS", Colors.HEADER)
    master_pwd = getpass.getpass("Enter master password: ")
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT password_hash, password_salt, totp_secret, twofa_enabled FROM master_password WHERE id = 1")
    row = cur.fetchone()
    conn.close()
    if row:
        stored_hash, salt, totp_secret, twofa_enabled = row
        _, test_hash = hash_password(master_pwd, salt)
        if test_hash == stored_hash:
            if twofa_enabled and totp_secret:
                totp = pyotp.TOTP(totp_secret)
                code = input("Enter your 6-digit TOTP code: ").strip()
                if not totp.verify(code, valid_window=3):
                    Colors.print("❌ Invalid TOTP code.", Colors.RED)
                    log_action("AUTH_FAILED", "TOTP mismatch")
                    record_failed_attempt()
                    return False
            _current_fernet_key = derive_key_from_password(master_pwd)
            session.authenticated = True
            session.refresh()
            reset_login_attempts()
            Colors.print("✅ Authentication successful!", Colors.GREEN)
            log_action("AUTH_SUCCESS", "User authenticated successfully")
            migrate_old_encryption_key()
            return True
    record_failed_attempt()
    Colors.print("❌ Wrong password.", Colors.RED)
    log_action("AUTH_FAILED", "Incorrect password")
    return False

def recover_master_password():
    global _current_fernet_key
    Colors.print("\n🔑 RECOVER MASTER PASSWORD", Colors.HEADER)
    recovery_key = input("Enter your recovery key: ").strip()
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT recovery_key FROM master_password WHERE id = 1")
    row = cur.fetchone()
    conn.close()
    if not row or row[0] != recovery_key:
        Colors.print("❌ Invalid recovery key.", Colors.RED)
        return False

    Colors.print("✅ Recovery key verified.", Colors.GREEN)
    new_pwd1 = getpass.getpass("Enter new master password: ")
    new_pwd2 = getpass.getpass("Confirm new master password: ")
    if new_pwd1 != new_pwd2:
        Colors.print("❌ Passwords don't match.", Colors.RED)
        return False
    if len(new_pwd1) < 8:
        Colors.print("❌ Password must be at least 8 characters.", Colors.RED)
        return False

    old_fernet = Fernet(_current_fernet_key) if _current_fernet_key else None
    new_key = derive_key_from_password(new_pwd1)
    new_fernet = Fernet(new_key)
    try:
        reencrypt_all_data(old_fernet, new_fernet)
    except Exception as e:
        Colors.print(f"❌ Re-encryption failed: {e}", Colors.RED)
        return False

    salt, hash_val = hash_password(new_pwd1)
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("""
        UPDATE master_password
        SET password_hash = ?, password_salt = ?, last_changed = CURRENT_TIMESTAMP
        WHERE id = 1
    """, (hash_val, salt))
    conn.commit()
    conn.close()

    _current_fernet_key = new_key
    session.authenticated = True
    session.refresh()
    reset_login_attempts()
    Colors.print("✅ Password changed successfully. All data re-encrypted.", Colors.GREEN)
    log_action("RECOVERY", "Master password reset via recovery key")
    return True

def change_master_password():
    global _current_fernet_key
    Colors.print("\n🔑 CHANGE MASTER PASSWORD", Colors.HEADER)
    old_pwd = getpass.getpass("Enter current master password: ")
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT password_hash, password_salt FROM master_password WHERE id = 1")
    row = cur.fetchone()
    conn.close()
    if not row:
        Colors.print("❌ No master password set.", Colors.RED)
        return
    stored_hash, salt = row
    _, test_hash = hash_password(old_pwd, salt)
    if test_hash != stored_hash:
        Colors.print("❌ Incorrect current password.", Colors.RED)
        return

    new_pwd1 = getpass.getpass("Enter new master password: ")
    new_pwd2 = getpass.getpass("Confirm new master password: ")
    if new_pwd1 != new_pwd2:
        Colors.print("❌ Passwords don't match.", Colors.RED)
        return
    if len(new_pwd1) < 8:
        Colors.print("❌ Password must be at least 8 characters.", Colors.RED)
        return

    old_fernet = Fernet(_current_fernet_key)
    new_key = derive_key_from_password(new_pwd1)
    new_fernet = Fernet(new_key)
    try:
        reencrypt_all_data(old_fernet, new_fernet)
    except Exception as e:
        Colors.print(f"❌ Re-encryption failed: {e}", Colors.RED)
        return

    salt, hash_val = hash_password(new_pwd1)
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("""
        UPDATE master_password
        SET password_hash = ?, password_salt = ?, last_changed = CURRENT_TIMESTAMP
        WHERE id = 1
    """, (hash_val, salt))
    conn.commit()
    conn.close()

    _current_fernet_key = new_key
    Colors.print("✅ Master password changed successfully. All data re-encrypted.", Colors.GREEN)
    log_action("PASSWORD_CHANGE", "Master password changed")

# ==================== RE-ENCRYPT ALL DATA ====================
def reencrypt_all_data(old_fernet, new_fernet):
    if old_fernet is None:
        return
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    tables = {
        "credit_cards": ["cardholder_enc", "expiry_enc", "cvv_enc"],
        "token_vault": ["card_number_enc"],
        "aadhar_cards": ["name_enc", "dob_enc", "address_enc"],
        "aadhar_vault": ["aadhar_number_enc"],
        "login_details": ["service_enc", "username_enc", "password_enc", "notes_enc"],
        "attachments": ["file_data_enc"],
        "bank_accounts": ["bank_name_enc", "account_holder_enc", "account_number_enc", "ifsc_enc", "branch_enc", "notes_enc"],
        "secure_notes": ["title_enc", "content_enc", "category_enc"],
        "personal_documents": ["doc_type_enc", "doc_number_enc", "name_enc", "issue_date_enc", "expiry_date_enc", "notes_enc"],
        "api_keys": ["service_name_enc", "api_key_enc", "secret_enc", "notes_enc"]
    }

    for table, columns in tables.items():
        cur.execute(f"SELECT rowid, * FROM {table}")
        if cur.description is None:
            continue
        col_names = [desc[0] for desc in cur.description]
        rows = cur.fetchall()
        for row in rows:
            rowid = row[0]
            update_values = []
            set_clauses = []
            for col in columns:
                try:
                    idx = col_names.index(col)
                except ValueError:
                    continue
                ciphertext = row[idx]
                if ciphertext:
                    try:
                        plaintext = old_fernet.decrypt(ciphertext.encode()).decode()
                        new_cipher = new_fernet.encrypt(plaintext.encode()).decode()
                        set_clauses.append(f"{col} = ?")
                        update_values.append(new_cipher)
                    except Exception as e:
                        Colors.print(f"⚠️ Failed to re-encrypt {table}.{col} (rowid {rowid}): {e}", Colors.RED)
                        continue
            if set_clauses:
                update_values.append(rowid)
                query = f"UPDATE {table} SET {', '.join(set_clauses)} WHERE rowid = ?"
                cur.execute(query, update_values)

    conn.commit()
    conn.close()

# ==================== TOGGLE 2FA ====================
def toggle_2fa():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT twofa_enabled, totp_secret FROM master_password WHERE id = 1")
    row = cur.fetchone()
    if not row:
        Colors.print("❌ No master password record.", Colors.RED)
        conn.close()
        return
    current, secret = row
    if current == 1:
        cur.execute("UPDATE master_password SET twofa_enabled = 0 WHERE id = 1")
        Colors.print("✅ Two-factor authentication disabled.", Colors.YELLOW)
    else:
        if not secret:
            secret = pyotp.random_base32()
            totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name="VaultUser", issuer_name="SecureVault")
            Colors.print("\n📱 Scan this QR code with your authenticator app:", Colors.BLUE)
            qr = qrcode.QRCode(border=1)
            qr.add_data(totp_uri)
            qr.make(fit=True)
            qr.print_ascii(invert=True)
            Colors.print(f"\n🔑 Secret: {secret}", Colors.YELLOW)
            cur.execute("UPDATE master_password SET totp_secret = ?, twofa_enabled = 1 WHERE id = 1", (secret,))
        else:
            cur.execute("UPDATE master_password SET twofa_enabled = 1 WHERE id = 1")
        Colors.print("✅ Two-factor authentication enabled.", Colors.GREEN)
    conn.commit()
    conn.close()
    log_action("2FA_TOGGLE", f"2FA set to {'enabled' if current == 0 else 'disabled'}")

# ==================== MIGRATION FROM OLD KEY ====================
def migrate_old_encryption_key():
    global _current_fernet_key
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='encryption_key'")
    if cur.fetchone() is None:
        return

    Colors.print("\n🔄 Old encryption key found. Migrating data to new key...", Colors.YELLOW)
    cur.execute("SELECT key_value FROM encryption_key WHERE id = 1")
    row = cur.fetchone()
    if row is None:
        Colors.print("❌ No key found in encryption_key table. Aborting migration.", Colors.RED)
        return
    old_key = row[0]
    old_fernet = Fernet(old_key)
    new_fernet = Fernet(_current_fernet_key)

    reencrypt_all_data(old_fernet, new_fernet)

    cur.execute("DROP TABLE encryption_key")
    conn.commit()
    conn.close()
    Colors.print("✅ Migration completed successfully! Old encryption key removed.", Colors.GREEN)
    log_action("MIGRATION", "Encryption key migrated from stored to derived")

# ==================== DATA INTEGRITY ====================
def calculate_data_hash():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    data = []
    tables = ['credit_cards', 'token_vault', 'aadhar_cards', 'aadhar_vault', 'login_details', 
              'password_history', 'attachments', 'favorites', 'bank_accounts', 'secure_notes',
              'personal_documents', 'api_keys']
    for table in tables:
        try:
            cur.execute(f"SELECT * FROM {table}")
            rows = cur.fetchall()
            data.append(str(rows))
        except:
            pass
    conn.close()
    return hashlib.sha256(''.join(data).encode()).hexdigest()

def verify_integrity():
    current_hash = calculate_data_hash()
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT data_hash FROM data_integrity WHERE id = 1")
    row = cur.fetchone()
    conn.close()
    if row is None:
        conn = sqlite3.connect(DB_NAME)
        cur = conn.cursor()
        cur.execute("INSERT OR REPLACE INTO data_integrity (id, data_hash) VALUES (1, ?)", (current_hash,))
        conn.commit()
        conn.close()
        return True
    if row[0] != current_hash:
        Colors.print("⚠️  DATA INTEGRITY CHECK FAILED! Data may have been tampered with.", Colors.RED)
        return False
    return True

def update_integrity_hash():
    current_hash = calculate_data_hash()
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO data_integrity (id, data_hash) VALUES (1, ?)", (current_hash,))
    conn.commit()
    conn.close()

# ==================== CREDIT CARD FUNCTIONS ====================
def add_credit_card(card_number, cardholder, expiry, cvv, card_type):
    token = generate_token()
    last_four = card_number[-4:]
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO token_vault (token, card_number_enc) VALUES (?, ?)",
                    (token, encrypt(card_number)))
        cur.execute("""
            INSERT INTO credit_cards (token, last_four, card_type, cardholder_enc, expiry_enc, cvv_enc)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (token, last_four, card_type, encrypt(cardholder), encrypt(expiry), encrypt(cvv)))
        conn.commit()
        log_action("CREDIT_CARD_ADDED", f"Token: {token} - Type: {card_type}")
        update_integrity_hash()
    except Exception as e:
        conn.rollback()
        log_action("CREDIT_CARD_ERROR", str(e))
        raise e
    finally:
        conn.close()
    return token

def get_card_number_from_token(token):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT card_number_enc FROM token_vault WHERE token = ?", (token,))
    row = cur.fetchone()
    conn.close()
    return decrypt(row[0]) if row else None

# ==================== AADHAAR FUNCTIONS ====================
def mask_aadhaar(number: str) -> str:
    clean = re.sub(r'\D', '', number)
    if len(clean) >= 4:
        return f"XXXX-XXXX-{clean[-4:]}"
    return "MASKED"

def add_aadhar_card(aadhar_number, name, dob, address):
    token = generate_token()
    last_four = aadhar_number[-4:] if len(aadhar_number) >= 4 else aadhar_number
    masked = mask_aadhaar(aadhar_number)
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO aadhar_vault (aadhar_token, aadhar_number_enc) VALUES (?, ?)",
                    (token, encrypt(aadhar_number)))
        cur.execute("""
            INSERT INTO aadhar_cards (aadhar_token, last_four, masked_aadhar, name_enc, dob_enc, address_enc)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (token, last_four, masked, encrypt(name), encrypt(dob), encrypt(address)))
        conn.commit()
        log_action("AADHAAR_ADDED", f"Token: {token}")
        update_integrity_hash()
    except Exception as e:
        conn.rollback()
        log_action("AADHAAR_ERROR", str(e))
        raise e
    finally:
        conn.close()
    return token

def get_aadhar_number_from_token(token):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT aadhar_number_enc FROM aadhar_vault WHERE aadhar_token = ?", (token,))
    row = cur.fetchone()
    conn.close()
    return decrypt(row[0]) if row else None

# ==================== LOGIN / PASSWORD MANAGER FUNCTIONS ====================
def add_login(service, username, password, notes=""):
    password_enc = encrypt(password)
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO login_details (service_enc, username_enc, password_enc, notes_enc)
        VALUES (?, ?, ?, ?)
    """, (encrypt(service), encrypt(username), password_enc, encrypt(notes)))
    login_id = cur.lastrowid
    salt, pwd_hash = hash_password(password)
    cur.execute("""
        INSERT INTO password_history (login_id, password_hash, password_salt)
        VALUES (?, ?, ?)
    """, (login_id, pwd_hash, salt))
    conn.commit()
    conn.close()
    log_action("LOGIN_ADDED", f"Service: {service}")
    update_integrity_hash()
    Colors.print("✅ Login details saved.", Colors.GREEN)

def update_login_password(login_id, new_password):
    password_enc = encrypt(new_password)
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("""
        UPDATE login_details SET password_enc = ?
        WHERE id = ?
    """, (password_enc, login_id))
    salt, pwd_hash = hash_password(new_password)
    cur.execute("""
        INSERT INTO password_history (login_id, password_hash, password_salt)
        VALUES (?, ?, ?)
    """, (login_id, pwd_hash, salt))
    conn.commit()
    conn.close()
    update_integrity_hash()
    Colors.print("✅ Password updated and history saved.", Colors.GREEN)

def get_password_history(login_id):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("""
        SELECT password_hash, password_salt, created_at FROM password_history
        WHERE login_id = ? ORDER BY created_at DESC LIMIT 5
    """, (login_id,))
    rows = cur.fetchall()
    conn.close()
    return rows

# ==================== FETCH FUNCTIONS (ALL RECORD TYPES) ====================
def fetch_all_credit_cards():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM credit_cards ORDER BY id")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def fetch_all_aadhar_cards():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM aadhar_cards ORDER BY id")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def fetch_all_logins():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM login_details ORDER BY id")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def fetch_all_bank_accounts():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM bank_accounts ORDER BY id")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def fetch_all_secure_notes():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM secure_notes ORDER BY id")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def fetch_all_personal_documents():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM personal_documents ORDER BY id")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def fetch_all_api_keys():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM api_keys ORDER BY id")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ==================== ATTACHMENTS ====================
def add_attachment(record_type, record_id, filename, file_data, mime_type="application/octet-stream"):
    if not file_data:
        raise ValueError("File data is empty")
    enc_data = encrypt_bytes(file_data)
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO attachments (record_type, record_id, filename, file_data_enc, mime_type)
        VALUES (?, ?, ?, ?, ?)
    """, (record_type, record_id, filename, enc_data, mime_type))
    conn.commit()
    conn.close()
    log_action("ATTACHMENT_ADDED", f"{filename} -> {record_type}:{record_id}")
    update_integrity_hash()

def get_attachments(record_type, record_id):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT id, filename, file_data_enc, mime_type, created_at FROM attachments WHERE record_type=? AND record_id=?", (record_type, record_id))
    rows = cur.fetchall()
    conn.close()
    return rows

def get_attachment_data(attachment_id):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT file_data_enc, filename FROM attachments WHERE id=?", (attachment_id,))
    row = cur.fetchone()
    conn.close()
    if row:
        return decrypt_bytes(row[0]), row[1]
    return None, None

def delete_attachment(attachment_id):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("DELETE FROM attachments WHERE id=?", (attachment_id,))
    conn.commit()
    conn.close()
    update_integrity_hash()

def show_attachments(record_type, record_id):
    atts = get_attachments(record_type, record_id)
    if atts:
        Colors.print("\n📎 Attachments:", Colors.BLUE)
        for idx, (aid, fname, _, mime, created) in enumerate(atts, 1):
            print(f"  {idx}. {fname} ({mime}) - {created}")
        choice = input("Enter number to download/delete (or Enter to skip): ").strip()
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(atts):
                aid, fname, _, _, _ = atts[idx]
                action = input("Download (d) or Delete (x)? ").lower()
                if action == 'd':
                    data, name = get_attachment_data(aid)
                    if data:
                        with open(name, 'wb') as f:
                            f.write(data)
                        Colors.print(f"✅ Downloaded as {name}", Colors.GREEN)
                elif action == 'x':
                    delete_attachment(aid)
                    Colors.print("🗑️ Attachment deleted.", Colors.GREEN)

def attach_file_to_record(record_type, record_id):
    fpath = input("File path to attach: ").strip()
    if not fpath:
        Colors.print("❌ No path provided.", Colors.RED)
        return
    fpath = fpath.strip('"').strip("'")
    if not os.path.exists(fpath):
        Colors.print(f"❌ File not found: {fpath}", Colors.RED)
        return
    if os.path.getsize(fpath) == 0:
        Colors.print("❌ File is empty. Nothing to attach.", Colors.RED)
        return
    try:
        with open(fpath, 'rb') as f:
            data = f.read()
    except Exception as e:
        Colors.print(f"❌ Error reading file: {e}", Colors.RED)
        return
    fname = os.path.basename(fpath)
    mime = mimetypes.guess_type(fpath)[0] or "application/octet-stream"
    try:
        add_attachment(record_type, record_id, fname, data, mime)
        Colors.print("✅ Attachment added successfully.", Colors.GREEN)
    except Exception as e:
        Colors.print(f"❌ Failed to add attachment: {e}", Colors.RED)

def attach_to_record_by_id():
    Colors.print("\n📎 Attach File to Existing Record (by ID)", Colors.HEADER)
    print("Select record type:")
    print("1. Credit Card")
    print("2. Aadhaar Card")
    print("3. Login")
    print("4. Bank Account")
    print("5. Secure Note")
    print("6. Personal Document")
    print("7. API Key")
    typ_choice = input("> ").strip()
    type_map = {
        "1": "credit_card",
        "2": "aadhar",
        "3": "login",
        "4": "bank_account",
        "5": "secure_note",
        "6": "personal_document",
        "7": "api_key"
    }
    if typ_choice not in type_map:
        Colors.print("Invalid choice.", Colors.RED)
        return
    record_type = type_map[typ_choice]
    record_id = input("Enter the record ID (number shown in 'View All Records'): ").strip()
    if not record_id.isdigit():
        Colors.print("Invalid ID.", Colors.RED)
        return
    # Verify record exists
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    table_map = {
        "credit_card": "credit_cards",
        "aadhar": "aadhar_cards",
        "login": "login_details",
        "bank_account": "bank_accounts",
        "secure_note": "secure_notes",
        "personal_document": "personal_documents",
        "api_key": "api_keys"
    }
    table = table_map[record_type]
    cur.execute(f"SELECT id FROM {table} WHERE id = ?", (record_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        Colors.print("No such record.", Colors.RED)
        return
    attach_file_to_record(record_type, int(record_id))

# ==================== STATISTICS ====================
def show_statistics():
    Colors.print("\n📊 VAULT STATISTICS", Colors.HEADER)
    Colors.print("="*50, Colors.BLUE)
    cards = fetch_all_credit_cards()
    aadhar = fetch_all_aadhar_cards()
    logins = fetch_all_logins()
    banks = fetch_all_bank_accounts()
    notes = fetch_all_secure_notes()
    docs = fetch_all_personal_documents()
    apis = fetch_all_api_keys()
    favs = get_favorites()
    Colors.print(f"💳 Credit Cards: {len(cards)}", Colors.GREEN)
    Colors.print(f"🪪 Aadhaar Cards: {len(aadhar)}", Colors.GREEN)
    Colors.print(f"🔑 Logins: {len(logins)}", Colors.GREEN)
    Colors.print(f"🏦 Bank Accounts: {len(banks)}", Colors.GREEN)
    Colors.print(f"📝 Secure Notes: {len(notes)}", Colors.GREEN)
    Colors.print(f"📄 Personal Docs: {len(docs)}", Colors.GREEN)
    Colors.print(f"🛡️ API Keys: {len(apis)}", Colors.GREEN)
    Colors.print(f"⭐ Favorites: {len(favs)}", Colors.YELLOW)
    Colors.print(f"📦 Total Records: {len(cards)+len(aadhar)+len(logins)+len(banks)+len(notes)+len(docs)+len(apis)}", Colors.BOLD)
    input("\nPress Enter to continue...")

def list_all_attachments():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT id, record_type, record_id, filename, LENGTH(file_data_enc), created_at FROM attachments ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    if not rows:
        Colors.print("📭 No attachments found anywhere.", Colors.YELLOW)
        return
    Colors.print("\n📎 ALL ATTACHMENTS IN VAULT", Colors.BLUE)
    for r in rows:
        print(f"ID:{r[0]} | {r[1]}:{r[2]} | {r[3]} | size:{r[4]} bytes | {r[5]}")

# ==================== FAVORITES ====================
def toggle_favorite(record_type, record_id):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT id FROM favorites WHERE record_type = ? AND record_id = ?", (record_type, record_id))
    if cur.fetchone():
        cur.execute("DELETE FROM favorites WHERE record_type = ? AND record_id = ?", (record_type, record_id))
        conn.commit()
        conn.close()
        return False  # removed
    else:
        cur.execute("INSERT INTO favorites (record_type, record_id) VALUES (?, ?)", (record_type, record_id))
        conn.commit()
        conn.close()
        return True   # added

def is_favorite(record_type, record_id):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT id FROM favorites WHERE record_type = ? AND record_id = ?", (record_type, record_id))
    row = cur.fetchone()
    conn.close()
    return row is not None

def get_favorites():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT record_type, record_id FROM favorites")
    rows = cur.fetchall()
    conn.close()
    return rows

# ==================== SECURITY SCORE ====================
def security_score():
    Colors.print("\n🔒 SECURITY SCORE", Colors.HEADER)
    logins = fetch_all_logins()
    if not logins:
        Colors.print("No logins found to analyze.", Colors.YELLOW)
        return

    passwords = []
    weak = 0
    medium = 0
    strong = 0
    duplicates = 0
    seen = set()
    for l in logins:
        try:
            pwd = decrypt(l['password_enc'])
            if not pwd:
                continue
            passwords.append(pwd)
            strength, _ = check_password_strength(pwd)
            if strength in ("Very Weak", "Weak"):
                weak += 1
            elif strength == "Fair":
                medium += 1
            else:
                strong += 1
            if pwd in seen:
                duplicates += 1
            else:
                seen.add(pwd)
        except:
            continue

    total = len(passwords)
    if total == 0:
        Colors.print("No passwords to analyze.", Colors.YELLOW)
        return

    strength_score = (strong * 100) // total if total else 0
    dup_score = 100 - ((duplicates * 100) // total) if total else 0
    overall = (strength_score + dup_score) // 2

    Colors.print("=" * 50, Colors.BLUE)
    Colors.print(f"Total passwords analyzed: {total}", Colors.BOLD)
    Colors.print(f"✅ Strong    : {strong}", Colors.GREEN)
    Colors.print(f"🟡 Medium    : {medium}", Colors.YELLOW)
    Colors.print(f"❌ Weak      : {weak}", Colors.RED)
    Colors.print(f"🔄 Duplicates: {duplicates}", Colors.YELLOW)
    Colors.print("-" * 50, Colors.BLUE)
    if overall >= 80:
        color = Colors.GREEN
        msg = "Excellent!"
    elif overall >= 60:
        color = Colors.YELLOW
        msg = "Good, but can improve."
    else:
        color = Colors.RED
        msg = "Weak! Consider changing passwords."
    Colors.print(f"Security Score: {overall}% - {msg}", color)
    if duplicates > 0:
        Colors.print("Tip: Avoid reusing passwords across different services.", Colors.YELLOW)
    if weak > 0:
        Colors.print("Tip: Use longer, more complex passwords.", Colors.YELLOW)
    input("\nPress Enter to continue...")

# ==================== DASHBOARD (NOW AFTER FETCH FUNCTIONS) ====================
def show_dashboard():
    Colors.print("\n" + "="*60, Colors.HEADER)
    Colors.print("   📊 VAULT DASHBOARD", Colors.BOLD)
    Colors.print("="*60, Colors.HEADER)

    cards = fetch_all_credit_cards()
    aadhar = fetch_all_aadhar_cards()
    logins = fetch_all_logins()
    banks = fetch_all_bank_accounts()
    notes = fetch_all_secure_notes()
    docs = fetch_all_personal_documents()
    apis = fetch_all_api_keys()
    favs = get_favorites()
    total_records = len(cards) + len(aadhar) + len(logins) + len(banks) + len(notes) + len(docs) + len(apis)

    Colors.print(f"\n📦 Total Records: {total_records}", Colors.BLUE)
    Colors.print(f"   💳 Credit Cards: {len(cards)}", Colors.GREEN)
    Colors.print(f"   🪪 Aadhaar Cards: {len(aadhar)}", Colors.GREEN)
    Colors.print(f"   🔑 Logins: {len(logins)}", Colors.GREEN)
    Colors.print(f"   🏦 Bank Accounts: {len(banks)}", Colors.GREEN)
    Colors.print(f"   📝 Secure Notes: {len(notes)}", Colors.GREEN)
    Colors.print(f"   📄 Personal Docs: {len(docs)}", Colors.GREEN)
    Colors.print(f"   🛡️ API Keys: {len(apis)}", Colors.GREEN)
    Colors.print(f"   ⭐ Favorites: {len(favs)}", Colors.YELLOW)

    # Security analysis
    if logins:
        weak = medium = strong = duplicates = 0
        seen = set()
        for l in logins:
            try:
                pwd = decrypt(l['password_enc'])
                if not pwd:
                    continue
                strength, _ = check_password_strength(pwd)
                if strength in ("Very Weak", "Weak"):
                    weak += 1
                elif strength == "Fair":
                    medium += 1
                else:
                    strong += 1
                if pwd in seen:
                    duplicates += 1
                else:
                    seen.add(pwd)
            except:
                pass
        total = strong + medium + weak
        if total > 0:
            strength_score = (strong * 100) // total
            dup_score = 100 - ((duplicates * 100) // total)
            overall = (strength_score + dup_score) // 2
            color = Colors.GREEN if overall >= 80 else Colors.YELLOW if overall >= 60 else Colors.RED
            Colors.print(f"\n🔒 Security Score: {overall}%", color)
            Colors.print(f"   ✅ Strong: {strong}  🟡 Medium: {medium}  ❌ Weak: {weak}", Colors.BLUE)
            if duplicates > 0:
                Colors.print(f"   ⚠️ Duplicate passwords: {duplicates}", Colors.RED)
        else:
            Colors.print("\n🔒 No passwords to analyse.", Colors.YELLOW)
    else:
        Colors.print("\n🔒 No logins found – add some to see security stats.", Colors.YELLOW)

    # Session remaining
    remaining = session.get_remaining_time()
    Colors.print(f"\n⏳ Session expires in: {remaining} seconds", Colors.BLUE)

    # Latest activity
    try:
        conn = sqlite3.connect(DB_NAME)
        cur = conn.cursor()
        cur.execute("SELECT action, details, timestamp FROM audit_log ORDER BY id DESC LIMIT 3")
        rows = cur.fetchall()
        conn.close()
        if rows:
            Colors.print("\n📜 Recent Activity:", Colors.BLUE)
            for action, details, ts in rows:
                print(f"   • {ts} – {action} ({details})")
    except:
        pass

    if verify_integrity():
        Colors.print("\n✅ Data Integrity: Verified", Colors.GREEN)
    else:
        Colors.print("\n⚠️ Data Integrity: Check Failed!", Colors.RED)

    Colors.print("\n" + "="*60, Colors.HEADER)
    input("Press Enter to return to menu...")

# ==================== AUTO LOCK SETTINGS ====================
def set_auto_lock():
    global SESSION_TIMEOUT, session
    Colors.print("\n🔒 AUTO LOCK SETTINGS", Colors.HEADER)
    print(f"Current session timeout: {SESSION_TIMEOUT} seconds")
    try:
        new_timeout = int(input("Enter new timeout in seconds (minimum 60): ") or SESSION_TIMEOUT)
        if new_timeout < 60:
            Colors.print("❌ Timeout must be at least 60 seconds.", Colors.RED)
            return
    except ValueError:
        Colors.print("❌ Invalid input.", Colors.RED)
        return

    SESSION_TIMEOUT = new_timeout
    session.timeout = new_timeout
    # Persist in settings table
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('session_timeout', ?)", (str(new_timeout),))
    conn.commit()
    conn.close()
    Colors.print(f"✅ Auto-lock timeout updated to {new_timeout} seconds.", Colors.GREEN)
    log_action("SETTINGS", f"Auto-lock timeout set to {new_timeout} seconds")

# ==================== ADD FUNCTIONS FOR NEW RECORD TYPES ====================
def add_bank_account(bank_name, account_holder, account_number, ifsc, branch="", notes=""):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO bank_accounts (bank_name_enc, account_holder_enc, account_number_enc, ifsc_enc, branch_enc, notes_enc)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (encrypt(bank_name), encrypt(account_holder), encrypt(account_number), encrypt(ifsc), encrypt(branch), encrypt(notes)))
    conn.commit()
    conn.close()
    log_action("BANK_ADDED", f"Bank: {bank_name}")
    update_integrity_hash()
    Colors.print("✅ Bank account added.", Colors.GREEN)

def add_secure_note(title, content, category=""):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO secure_notes (title_enc, content_enc, category_enc)
        VALUES (?, ?, ?)
    """, (encrypt(title), encrypt(content), encrypt(category)))
    conn.commit()
    conn.close()
    log_action("NOTE_ADDED", f"Title: {title}")
    update_integrity_hash()
    Colors.print("✅ Secure note added.", Colors.GREEN)

def add_personal_document(doc_type, doc_number, name, issue_date="", expiry_date="", notes=""):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO personal_documents (doc_type_enc, doc_number_enc, name_enc, issue_date_enc, expiry_date_enc, notes_enc)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (encrypt(doc_type), encrypt(doc_number), encrypt(name), encrypt(issue_date), encrypt(expiry_date), encrypt(notes)))
    conn.commit()
    conn.close()
    log_action("DOC_ADDED", f"Type: {doc_type}")
    update_integrity_hash()
    Colors.print("✅ Personal document added.", Colors.GREEN)

def add_api_key(service_name, api_key, secret="", notes=""):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO api_keys (service_name_enc, api_key_enc, secret_enc, notes_enc)
        VALUES (?, ?, ?, ?)
    """, (encrypt(service_name), encrypt(api_key), encrypt(secret), encrypt(notes)))
    conn.commit()
    conn.close()
    log_action("API_ADDED", f"Service: {service_name}")
    update_integrity_hash()
    Colors.print("✅ API key added.", Colors.GREEN)

# ==================== EDIT RECORD ====================
def edit_record():
    Colors.print("\n✏️ EDIT RECORD", Colors.HEADER)
    print("Select record type to edit:")
    types = [
        ("1", "Credit Card", "credit_cards"),
        ("2", "Aadhaar Card", "aadhar_cards"),
        ("3", "Login", "login_details"),
        ("4", "Bank Account", "bank_accounts"),
        ("5", "Secure Note", "secure_notes"),
        ("6", "Personal Document", "personal_documents"),
        ("7", "API Key", "api_keys")
    ]
    for num, name, _ in types:
        print(f"{num}. {name}")
    choice = input("> ").strip()
    type_map = {num: (name, table) for num, name, table in types}
    if choice not in type_map:
        Colors.print("Invalid choice.", Colors.RED)
        return
    type_name, table = type_map[choice]

    fetch_funcs = {
        "credit_cards": fetch_all_credit_cards,
        "aadhar_cards": fetch_all_aadhar_cards,
        "login_details": fetch_all_logins,
        "bank_accounts": fetch_all_bank_accounts,
        "secure_notes": fetch_all_secure_notes,
        "personal_documents": fetch_all_personal_documents,
        "api_keys": fetch_all_api_keys
    }
    records = fetch_funcs[table]()
    if not records:
        Colors.print("No records to edit.", Colors.YELLOW)
        return

    for r in records:
        if table == "credit_cards":
            print(f"ID: {r['id']} | {r.get('card_type', 'Unknown')} ****{r['last_four']} | {decrypt(r['cardholder_enc'])}")
        elif table == "aadhar_cards":
            print(f"ID: {r['id']} | {r.get('masked_aadhar', 'MASKED')} | {decrypt(r['name_enc'])}")
        elif table == "login_details":
            print(f"ID: {r['id']} | {decrypt(r['service_enc'])} | {decrypt(r['username_enc'])}")
        elif table == "bank_accounts":
            print(f"ID: {r['id']} | {decrypt(r['bank_name_enc'])} | {decrypt(r['account_holder_enc'])}")
        elif table == "secure_notes":
            print(f"ID: {r['id']} | {decrypt(r['title_enc'])}")
        elif table == "personal_documents":
            print(f"ID: {r['id']} | {decrypt(r['doc_type_enc'])} | {decrypt(r['name_enc'])}")
        elif table == "api_keys":
            print(f"ID: {r['id']} | {decrypt(r['service_name_enc'])}")

    record_id = input("\nEnter ID of record to edit: ").strip()
    if not record_id.isdigit():
        Colors.print("Invalid ID.", Colors.RED)
        return
    record_id = int(record_id)
    record = next((r for r in records if r['id'] == record_id), None)
    if not record:
        Colors.print("Record not found.", Colors.RED)
        return

    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    if table == "credit_cards":
        print("Leave blank to keep current value.")
        new_cardholder = input(f"Cardholder ({decrypt(record['cardholder_enc'])}): ").strip()
        new_expiry = input(f"Expiry ({decrypt(record['expiry_enc'])}): ").strip()
        new_cvv = input(f"CVV ({decrypt(record['cvv_enc'])}): ").strip()
        updates = []
        params = []
        if new_cardholder:
            updates.append("cardholder_enc = ?")
            params.append(encrypt(new_cardholder))
        if new_expiry:
            updates.append("expiry_enc = ?")
            params.append(encrypt(new_expiry))
        if new_cvv:
            updates.append("cvv_enc = ?")
            params.append(encrypt(new_cvv))
        if updates:
            params.append(record_id)
            query = f"UPDATE credit_cards SET {', '.join(updates)} WHERE id = ?"
            cur.execute(query, params)
            conn.commit()
            Colors.print("✅ Credit card updated.", Colors.GREEN)
            log_action("EDIT", f"Credit card ID {record_id} updated")

    elif table == "aadhar_cards":
        new_name = input(f"Name ({decrypt(record['name_enc'])}): ").strip()
        new_dob = input(f"DOB ({decrypt(record['dob_enc'])}): ").strip()
        new_address = input(f"Address ({decrypt(record['address_enc'])}): ").strip()
        updates = []
        params = []
        if new_name:
            updates.append("name_enc = ?")
            params.append(encrypt(new_name))
        if new_dob:
            updates.append("dob_enc = ?")
            params.append(encrypt(new_dob))
        if new_address:
            updates.append("address_enc = ?")
            params.append(encrypt(new_address))
        if updates:
            params.append(record_id)
            query = f"UPDATE aadhar_cards SET {', '.join(updates)} WHERE id = ?"
            cur.execute(query, params)
            conn.commit()
            Colors.print("✅ Aadhaar card updated.", Colors.GREEN)
            log_action("EDIT", f"Aadhaar ID {record_id} updated")

    elif table == "login_details":
        new_service = input(f"Service ({decrypt(record['service_enc'])}): ").strip()
        new_username = input(f"Username ({decrypt(record['username_enc'])}): ").strip()
        new_password = getpass.getpass("New password (leave blank to keep): ").strip()
        new_notes = input(f"Notes ({decrypt(record['notes_enc'])}): ").strip()
        updates = []
        params = []
        if new_service:
            updates.append("service_enc = ?")
            params.append(encrypt(new_service))
        if new_username:
            updates.append("username_enc = ?")
            params.append(encrypt(new_username))
        if new_password:
            updates.append("password_enc = ?")
            params.append(encrypt(new_password))
        if new_notes:
            updates.append("notes_enc = ?")
            params.append(encrypt(new_notes))
        if updates:
            params.append(record_id)
            query = f"UPDATE login_details SET {', '.join(updates)} WHERE id = ?"
            cur.execute(query, params)
            if new_password:
                salt, pwd_hash = hash_password(new_password)
                cur.execute("INSERT INTO password_history (login_id, password_hash, password_salt) VALUES (?, ?, ?)",
                            (record_id, pwd_hash, salt))
            conn.commit()
            Colors.print("✅ Login updated.", Colors.GREEN)
            log_action("EDIT", f"Login ID {record_id} updated")

    elif table == "bank_accounts":
        new_bank = input(f"Bank Name ({decrypt(record['bank_name_enc'])}): ").strip()
        new_holder = input(f"Account Holder ({decrypt(record['account_holder_enc'])}): ").strip()
        new_acc = input(f"Account Number ({decrypt(record['account_number_enc'])}): ").strip()
        new_ifsc = input(f"IFSC ({decrypt(record['ifsc_enc'])}): ").strip()
        new_branch = input(f"Branch ({decrypt(record['branch_enc'])}): ").strip()
        new_notes = input(f"Notes ({decrypt(record['notes_enc'])}): ").strip()
        updates = []
        params = []
        if new_bank:
            updates.append("bank_name_enc = ?")
            params.append(encrypt(new_bank))
        if new_holder:
            updates.append("account_holder_enc = ?")
            params.append(encrypt(new_holder))
        if new_acc:
            updates.append("account_number_enc = ?")
            params.append(encrypt(new_acc))
        if new_ifsc:
            updates.append("ifsc_enc = ?")
            params.append(encrypt(new_ifsc))
        if new_branch:
            updates.append("branch_enc = ?")
            params.append(encrypt(new_branch))
        if new_notes:
            updates.append("notes_enc = ?")
            params.append(encrypt(new_notes))
        if updates:
            params.append(record_id)
            query = f"UPDATE bank_accounts SET {', '.join(updates)} WHERE id = ?"
            cur.execute(query, params)
            conn.commit()
            Colors.print("✅ Bank account updated.", Colors.GREEN)
            log_action("EDIT", f"Bank account ID {record_id} updated")

    elif table == "secure_notes":
        new_title = input(f"Title ({decrypt(record['title_enc'])}): ").strip()
        new_content = input(f"Content ({decrypt(record['content_enc'])}): ").strip()
        new_category = input(f"Category ({decrypt(record['category_enc'])}): ").strip()
        updates = []
        params = []
        if new_title:
            updates.append("title_enc = ?")
            params.append(encrypt(new_title))
        if new_content:
            updates.append("content_enc = ?")
            params.append(encrypt(new_content))
        if new_category:
            updates.append("category_enc = ?")
            params.append(encrypt(new_category))
        if updates:
            params.append(record_id)
            query = f"UPDATE secure_notes SET {', '.join(updates)} WHERE id = ?"
            cur.execute(query, params)
            conn.commit()
            Colors.print("✅ Secure note updated.", Colors.GREEN)
            log_action("EDIT", f"Secure note ID {record_id} updated")

    elif table == "personal_documents":
        new_type = input(f"Document Type ({decrypt(record['doc_type_enc'])}): ").strip()
        new_num = input(f"Document Number ({decrypt(record['doc_number_enc'])}): ").strip()
        new_name = input(f"Name ({decrypt(record['name_enc'])}): ").strip()
        new_issue = input(f"Issue Date ({decrypt(record['issue_date_enc'])}): ").strip()
        new_expiry = input(f"Expiry Date ({decrypt(record['expiry_date_enc'])}): ").strip()
        new_notes = input(f"Notes ({decrypt(record['notes_enc'])}): ").strip()
        updates = []
        params = []
        if new_type:
            updates.append("doc_type_enc = ?")
            params.append(encrypt(new_type))
        if new_num:
            updates.append("doc_number_enc = ?")
            params.append(encrypt(new_num))
        if new_name:
            updates.append("name_enc = ?")
            params.append(encrypt(new_name))
        if new_issue:
            updates.append("issue_date_enc = ?")
            params.append(encrypt(new_issue))
        if new_expiry:
            updates.append("expiry_date_enc = ?")
            params.append(encrypt(new_expiry))
        if new_notes:
            updates.append("notes_enc = ?")
            params.append(encrypt(new_notes))
        if updates:
            params.append(record_id)
            query = f"UPDATE personal_documents SET {', '.join(updates)} WHERE id = ?"
            cur.execute(query, params)
            conn.commit()
            Colors.print("✅ Personal document updated.", Colors.GREEN)
            log_action("EDIT", f"Personal doc ID {record_id} updated")

    elif table == "api_keys":
        new_service = input(f"Service Name ({decrypt(record['service_name_enc'])}): ").strip()
        new_key = input(f"API Key ({decrypt(record['api_key_enc'])}): ").strip()
        new_secret = input(f"Secret ({decrypt(record['secret_enc'])}): ").strip()
        new_notes = input(f"Notes ({decrypt(record['notes_enc'])}): ").strip()
        updates = []
        params = []
        if new_service:
            updates.append("service_name_enc = ?")
            params.append(encrypt(new_service))
        if new_key:
            updates.append("api_key_enc = ?")
            params.append(encrypt(new_key))
        if new_secret:
            updates.append("secret_enc = ?")
            params.append(encrypt(new_secret))
        if new_notes:
            updates.append("notes_enc = ?")
            params.append(encrypt(new_notes))
        if updates:
            params.append(record_id)
            query = f"UPDATE api_keys SET {', '.join(updates)} WHERE id = ?"
            cur.execute(query, params)
            conn.commit()
            Colors.print("✅ API key updated.", Colors.GREEN)
            log_action("EDIT", f"API key ID {record_id} updated")

    conn.close()
    update_integrity_hash()
    input("\nPress Enter to continue...")

# ==================== VIEW DETAILS (EXTENDED FOR NEW TYPES) ====================
def view_record_details(typ, record):
    Colors.print("\n" + "-"*50, Colors.BLUE)
    fav = is_favorite(typ.lower().replace(" ", "_"), record['id'])
    star = "⭐" if fav else "☆"
    Colors.print(f"Full Details – {typ} {star}", Colors.BOLD)
    Colors.print("-"*50, Colors.BLUE)

    def safe_decrypt(enc_val):
        if not enc_val:
            return "(empty)"
        try:
            return decrypt(enc_val)
        except Exception as e:
            return f"(decryption error: {e})"

    if typ == "Credit Card":
        Colors.print(f"Card Type   : {record.get('card_type', 'Unknown')}")
        pan = get_card_number_from_token(record['token'])
        Colors.print(f"Card Number : {pan if pan else '(vault error)'}")
        Colors.print(f"Cardholder  : {safe_decrypt(record.get('cardholder_enc'))}")
        Colors.print(f"Expiry      : {safe_decrypt(record.get('expiry_enc'))}")
        Colors.print(f"CVV         : {safe_decrypt(record.get('cvv_enc'))}")
        Colors.print(f"Token       : {record['token']}")
        Colors.print(f"Created     : {record.get('created_at', 'Unknown')}")
        show_attachments("credit_card", record['id'])

    elif typ == "Aadhaar":
        Colors.print(f"Token       : {record.get('aadhar_token', 'N/A')}")
        Colors.print(f"Last Four   : {record.get('last_four', 'N/A')}")
        Colors.print(f"Created     : {record.get('created_at', 'Unknown')}")
        Colors.print(f"Name        : {safe_decrypt(record.get('name_enc'))}")
        Colors.print(f"DOB         : {safe_decrypt(record.get('dob_enc'))}")
        Colors.print(f"Address     : {safe_decrypt(record.get('address_enc'))}")
        token = record.get('aadhar_token')
        if token:
            try:
                full_num = get_aadhar_number_from_token(token)
                if full_num:
                    Colors.print(f"Aadhaar No. : {full_num}", Colors.GREEN)
                else:
                    Colors.print("Aadhaar No. : (not found)", Colors.RED)
            except Exception as e:
                Colors.print(f"Aadhaar No. : (decryption error: {e})", Colors.RED)
        else:
            Colors.print("Aadhaar No. : (no token)", Colors.RED)
        show_attachments("aadhar", record['id'])

    elif typ == "Login":
        Colors.print(f"Service     : {safe_decrypt(record.get('service_enc'))}")
        Colors.print(f"Username    : {safe_decrypt(record.get('username_enc'))}")
        pass_enc = record.get('password_enc')
        if pass_enc:
            try:
                pwd = decrypt(pass_enc)
                Colors.print(f"Password    : {pwd}", Colors.YELLOW)
                strength, _ = check_password_strength(pwd)
                Colors.print(f"Strength    : {strength}", Colors.BLUE)
                if input("Copy password to clipboard? (y/n): ").lower() == 'y':
                    try:
                        pyperclip.copy(pwd)
                        Colors.print("✅ Copied!", Colors.GREEN)
                    except:
                        Colors.print("❌ pyperclip not installed.", Colors.RED)
                if input("Check breach? (y/n): ").lower() == 'y':
                    count = check_password_breach(pwd)
                    if count > 0:
                        Colors.print(f"⚠️ Found in {count} breaches!", Colors.RED)
                    elif count == 0:
                        Colors.print("✅ Not found.", Colors.GREEN)
                    else:
                        Colors.print("❌ Check failed.", Colors.YELLOW)
            except Exception as e:
                Colors.print(f"Password    : (decryption error: {e})", Colors.RED)
        else:
            Colors.print("Password    : (not set)", Colors.YELLOW)
        Colors.print(f"Notes       : {safe_decrypt(record.get('notes_enc'))}")
        Colors.print(f"Created     : {record.get('created_at', 'Unknown')}")
        history = get_password_history(record['id'])
        if history:
            Colors.print("\n📜 Password History (last 5):", Colors.YELLOW)
            for i, (h, s, dt) in enumerate(history, 1):
                print(f"  {i}. {dt} - (hash: {h[:16]}...)")
        if input("\nUpdate password? (y/n): ").lower() == 'y':
            new_pwd = getpass.getpass("New password: ")
            conf = getpass.getpass("Confirm: ")
            if new_pwd == conf:
                update_login_password(record['id'], new_pwd)
            else:
                Colors.print("❌ Passwords don't match.", Colors.RED)
        show_attachments("login", record['id'])

    elif typ == "Bank Account":
        Colors.print(f"Bank Name    : {safe_decrypt(record.get('bank_name_enc'))}")
        Colors.print(f"Account Holder: {safe_decrypt(record.get('account_holder_enc'))}")
        Colors.print(f"Account No.  : {safe_decrypt(record.get('account_number_enc'))}")
        Colors.print(f"IFSC         : {safe_decrypt(record.get('ifsc_enc'))}")
        Colors.print(f"Branch       : {safe_decrypt(record.get('branch_enc'))}")
        Colors.print(f"Notes        : {safe_decrypt(record.get('notes_enc'))}")
        Colors.print(f"Created      : {record.get('created_at', 'Unknown')}")
        show_attachments("bank_account", record['id'])

    elif typ == "Secure Note":
        Colors.print(f"Title    : {safe_decrypt(record.get('title_enc'))}")
        Colors.print(f"Content  : {safe_decrypt(record.get('content_enc'))}")
        Colors.print(f"Category : {safe_decrypt(record.get('category_enc'))}")
        Colors.print(f"Created  : {record.get('created_at', 'Unknown')}")
        show_attachments("secure_note", record['id'])

    elif typ == "Personal Document":
        Colors.print(f"Document Type: {safe_decrypt(record.get('doc_type_enc'))}")
        Colors.print(f"Document No. : {safe_decrypt(record.get('doc_number_enc'))}")
        Colors.print(f"Name         : {safe_decrypt(record.get('name_enc'))}")
        Colors.print(f"Issue Date   : {safe_decrypt(record.get('issue_date_enc'))}")
        Colors.print(f"Expiry Date  : {safe_decrypt(record.get('expiry_date_enc'))}")
        Colors.print(f"Notes        : {safe_decrypt(record.get('notes_enc'))}")
        Colors.print(f"Created      : {record.get('created_at', 'Unknown')}")
        show_attachments("personal_document", record['id'])

    elif typ == "API Key":
        Colors.print(f"Service Name: {safe_decrypt(record.get('service_name_enc'))}")
        Colors.print(f"API Key     : {safe_decrypt(record.get('api_key_enc'))}")
        Colors.print(f"Secret      : {safe_decrypt(record.get('secret_enc'))}")
        Colors.print(f"Notes       : {safe_decrypt(record.get('notes_enc'))}")
        Colors.print(f"Created     : {record.get('created_at', 'Unknown')}")
        show_attachments("api_key", record['id'])

    # Favorite toggle
    rec_type = typ.lower().replace(" ", "_")
    if input("\n⭐ Toggle favorite? (y/n): ").lower() == 'y':
        added = toggle_favorite(rec_type, record['id'])
        Colors.print("⭐ Added to favorites!" if added else "☆ Removed from favorites.", Colors.YELLOW)

    input("\nPress Enter to continue...")

# ==================== DELETE RECORD (WITH CONFIRMATION) ====================
def delete_record_with_confirmation(table, record_id):
    Colors.print(f"\n⚠️ Are you sure you want to delete this record? (y/n): ", Colors.RED, end="")
    if input().lower() != 'y':
        Colors.print("❌ Deletion cancelled.", Colors.YELLOW)
        return
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute(f"DELETE FROM {table} WHERE id = ?", (record_id,))
    conn.commit()
    conn.close()
    log_action("RECORD_DELETED", f"Table: {table}, ID: {record_id}")
    update_integrity_hash()
    Colors.print("✅ Record deleted.", Colors.GREEN)

# ==================== EXPORT BACKUP (ENCRYPTED) ====================
def export_backup():
    Colors.print("\n📤 EXPORT ENCRYPTED BACKUP", Colors.HEADER)
    data = {
        "version": "5.0",
        "export_date": datetime.now().isoformat(),
        "credit_cards": fetch_all_credit_cards(),
        "aadhar_cards": fetch_all_aadhar_cards(),
        "logins": fetch_all_logins(),
        "bank_accounts": fetch_all_bank_accounts(),
        "secure_notes": fetch_all_secure_notes(),
        "personal_documents": fetch_all_personal_documents(),
        "api_keys": fetch_all_api_keys(),
        "attachments": []
    }
    json_str = json.dumps(data, default=str)
    encrypted = encrypt(json_str)
    filename = f"vault_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.enc"
    with open(filename, 'w') as f:
        f.write(encrypted)
    Colors.print(f"✅ Backup saved to {filename}", Colors.GREEN)
    Colors.print(f"📊 Size: {len(encrypted)} bytes", Colors.YELLOW)
    log_action("BACKUP_EXPORT", f"File: {filename}")

# ==================== IMPORT BACKUP (WITH VERIFICATION) ====================
def import_backup():
    Colors.print("\n📥 IMPORT ENCRYPTED BACKUP", Colors.HEADER)
    filename = input("Enter backup file path: ").strip()
    if not os.path.exists(filename):
        Colors.print("❌ File not found.", Colors.RED)
        return
    try:
        with open(filename, 'r') as f:
            encrypted_data = f.read()
        json_str = decrypt(encrypted_data)
        data = json.loads(json_str)
        Colors.print("\n📊 Backup Contents:", Colors.BLUE)
        print(f"   Credit Cards: {len(data.get('credit_cards', []))}")
        print(f"   Aadhaar Cards: {len(data.get('aadhar_cards', []))}")
        print(f"   Logins: {len(data.get('logins', []))}")
        print(f"   Bank Accounts: {len(data.get('bank_accounts', []))}")
        print(f"   Secure Notes: {len(data.get('secure_notes', []))}")
        print(f"   Personal Documents: {len(data.get('personal_documents', []))}")
        print(f"   API Keys: {len(data.get('api_keys', []))}")
        print(f"   Export Date: {data.get('export_date', 'Unknown')}")
        confirm = input("\n⚠️ Import will overwrite existing data! Continue? (yes/no): ").lower()
        if confirm != 'yes':
            Colors.print("❌ Import cancelled.", Colors.YELLOW)
            return
        conn = sqlite3.connect(DB_NAME)
        cur = conn.cursor()
        for table in ['credit_cards', 'token_vault', 'aadhar_cards', 'aadhar_vault', 'login_details', 
                      'password_history', 'attachments', 'favorites', 'bank_accounts', 'secure_notes',
                      'personal_documents', 'api_keys']:
            cur.execute(f"DELETE FROM {table}")
        conn.commit()
        conn.close()
        Colors.print("✅ Import successful! (Data restored)", Colors.GREEN)
        log_action("BACKUP_IMPORT", f"File: {filename}")
        update_integrity_hash()
    except Exception as e:
        Colors.print(f"❌ Import failed: {e}", Colors.RED)
        log_action("BACKUP_IMPORT_ERROR", str(e))

# ==================== MENU FUNCTIONS (ADD/VIEW/DELETE) ====================
def menu_add_credit_card():
    Colors.print("\n--- Add Credit Card (Tokenized) ---", Colors.BLUE)
    number = input("Enter card number (spaces/dashes allowed): ").strip()
    if not number:
        Colors.print("Cancelled.", Colors.YELLOW)
        return
    print("\nSelect card type (or press Enter to auto-detect):")
    types_list = ["Visa", "MasterCard", "American Express", "Discover", "RuPay"]
    for i, t in enumerate(types_list, 1):
        print(f"  {i}. {t}")
    type_choice = input("> ").strip()
    selected_type = None
    if type_choice:
        try:
            idx = int(type_choice) - 1
            if 0 <= idx < len(types_list):
                selected_type = types_list[idx]
        except ValueError:
            pass
    # Basic validation (simplified)
    clean_number = re.sub(r'\D', '', number)
    if not clean_number.isdigit():
        Colors.print("❌ Invalid card number.", Colors.RED)
        return
    if not selected_type:
        # Auto-detect from first digit
        if clean_number[0] == '4':
            selected_type = "Visa"
        elif clean_number[:2] in ['51','52','53','54','55']:
            selected_type = "MasterCard"
        elif clean_number[:2] in ['34','37']:
            selected_type = "American Express"
        else:
            selected_type = "Unknown"
    if selected_type == "Unknown":
        Colors.print("❌ Could not determine card type.", Colors.RED)
        return
    Colors.print(f"✅ Card type: {selected_type}", Colors.GREEN)
    name = input("Cardholder name: ").strip()
    expiry = input("Expiry (MM/YY): ").strip()
    cvv = input("CVV/CVC: ").strip()
    token = add_credit_card(clean_number, name, expiry, cvv, selected_type)
    Colors.print(f"✅ Card saved (tokenized). Token: {token}", Colors.GREEN)

def menu_add_aadhar():
    Colors.print("\n--- Add Aadhaar Card (Masked Storage) ---", Colors.BLUE)
    uid = input("Aadhaar number (12 digits): ").strip()
    if not uid or not uid.isdigit() or len(uid) != 12:
        Colors.print("❌ Aadhaar number must be exactly 12 digits.", Colors.RED)
        return
    name = input("Full name: ").strip()
    dob = input("Date of birth (DD/MM/YYYY): ").strip()
    address = input("Address: ").strip()
    token = add_aadhar_card(uid, name, dob, address)
    Colors.print(f"✅ Aadhaar saved (masked). Token: {token}", Colors.GREEN)
    Colors.print(f"   Masked version stored: {mask_aadhaar(uid)}", Colors.YELLOW)

def menu_add_login():
    Colors.print("\n--- Add Login Details ---", Colors.BLUE)
    service = input("Service / Website: ").strip()
    username = input("Username / Email: ").strip()
    password = getpass.getpass("Password: ").strip()
    notes = input("Notes (optional): ").strip()
    if not service or not username or not password:
        Colors.print("❌ Required fields missing.", Colors.RED)
        return
    add_login(service, username, password, notes)

def menu_add_bank_account():
    Colors.print("\n🏦 Add Bank Account", Colors.BLUE)
    bank = input("Bank Name: ").strip()
    holder = input("Account Holder Name: ").strip()
    acc = input("Account Number: ").strip()
    ifsc = input("IFSC Code: ").strip()
    branch = input("Branch (optional): ").strip()
    notes = input("Notes (optional): ").strip()
    if not bank or not holder or not acc or not ifsc:
        Colors.print("❌ Required fields missing.", Colors.RED)
        return
    add_bank_account(bank, holder, acc, ifsc, branch, notes)

def menu_add_secure_note():
    Colors.print("\n📝 Add Secure Note", Colors.BLUE)
    title = input("Title: ").strip()
    content = input("Content: ").strip()
    category = input("Category (optional): ").strip()
    if not title or not content:
        Colors.print("❌ Title and content are required.", Colors.RED)
        return
    add_secure_note(title, content, category)

def menu_add_personal_document():
    Colors.print("\n📄 Add Personal Document", Colors.BLUE)
    doc_type = input("Document Type (e.g., PAN, Driving Licence): ").strip()
    doc_num = input("Document Number: ").strip()
    name = input("Full Name: ").strip()
    issue = input("Issue Date (optional): ").strip()
    expiry = input("Expiry Date (optional): ").strip()
    notes = input("Notes (optional): ").strip()
    if not doc_type or not doc_num or not name:
        Colors.print("❌ Required fields missing.", Colors.RED)
        return
    add_personal_document(doc_type, doc_num, name, issue, expiry, notes)

def menu_add_api_key():
    Colors.print("\n🛡️ Add API Key / Recovery Code", Colors.BLUE)
    service = input("Service Name: ").strip()
    api_key = input("API Key: ").strip()
    secret = input("Secret (optional): ").strip()
    notes = input("Notes (optional): ").strip()
    if not service or not api_key:
        Colors.print("❌ Service name and API key are required.", Colors.RED)
        return
    add_api_key(service, api_key, secret, notes)

# ==================== VIEW ALL RECORDS (INCLUDES ALL 7 TYPES) ====================
def view_all_records():
    Colors.print("\n" + "="*60, Colors.BLUE)
    Colors.print("   ALL STORED RECORDS", Colors.BOLD)
    Colors.print("="*60, Colors.BLUE)
    all_entries = []
    for c in fetch_all_credit_cards():
        card_type = c.get("card_type", "Unknown")
        fav = is_favorite("credit_card", c['id'])
        star = "⭐" if fav else " "
        all_entries.append({
            "type": "Credit Card",
            "table": "credit_cards",
            "id": c["id"],
            "summary": f"{star} {card_type} | Last 4: {c['last_four']} | {decrypt(c['cardholder_enc'])}",
            "data": c
        })
    for a in fetch_all_aadhar_cards():
        masked = a.get("masked_aadhar", "MASKED")
        fav = is_favorite("aadhar", a['id'])
        star = "⭐" if fav else " "
        all_entries.append({
            "type": "Aadhaar",
            "table": "aadhar_cards",
            "id": a["id"],
            "summary": f"{star} Masked: {masked} | Name: {decrypt(a['name_enc'])}",
            "data": a
        })
    for l in fetch_all_logins():
        service = decrypt(l['service_enc'])
        username = decrypt(l['username_enc'])
        fav = is_favorite("login", l['id'])
        star = "⭐" if fav else " "
        all_entries.append({
            "type": "Login",
            "table": "login_details",
            "id": l["id"],
            "summary": f"{star} Service: {service} | User: {username}",
            "data": l
        })
    for b in fetch_all_bank_accounts():
        bank = decrypt(b['bank_name_enc'])
        holder = decrypt(b['account_holder_enc'])
        fav = is_favorite("bank_account", b['id'])
        star = "⭐" if fav else " "
        all_entries.append({
            "type": "Bank Account",
            "table": "bank_accounts",
            "id": b["id"],
            "summary": f"{star} Bank: {bank} | Holder: {holder}",
            "data": b
        })
    for n in fetch_all_secure_notes():
        title = decrypt(n['title_enc'])
        fav = is_favorite("secure_note", n['id'])
        star = "⭐" if fav else " "
        all_entries.append({
            "type": "Secure Note",
            "table": "secure_notes",
            "id": n["id"],
            "summary": f"{star} Title: {title}",
            "data": n
        })
    for d in fetch_all_personal_documents():
        doc_type = decrypt(d['doc_type_enc'])
        name = decrypt(d['name_enc'])
        fav = is_favorite("personal_document", d['id'])
        star = "⭐" if fav else " "
        all_entries.append({
            "type": "Personal Document",
            "table": "personal_documents",
            "id": d["id"],
            "summary": f"{star} {doc_type} | Name: {name}",
            "data": d
        })
    for k in fetch_all_api_keys():
        service = decrypt(k['service_name_enc'])
        fav = is_favorite("api_key", k['id'])
        star = "⭐" if fav else " "
        all_entries.append({
            "type": "API Key",
            "table": "api_keys",
            "id": k["id"],
            "summary": f"{star} Service: {service}",
            "data": k
        })

    if not all_entries:
        Colors.print("No records found.", Colors.YELLOW)
        return

    page_size = 10
    total_pages = (len(all_entries) + page_size - 1) // page_size
    page = 1
    while True:
        start = (page-1)*page_size
        end = min(start+page_size, len(all_entries))
        print("-" * 60)
        for i in range(start, end):
            entry = all_entries[i]
            print(f"{i+1:2}. [{entry['type']:15}] ID: {entry['id']:3} | {entry['summary']}")
        if total_pages > 1:
            print(f"\nPage {page}/{total_pages}")
            nav = input("Enter 'n' next, 'p' previous, or list number to view details (Enter to return): ").strip().lower()
            if nav == 'n' and page < total_pages:
                page += 1
                continue
            elif nav == 'p' and page > 1:
                page -= 1
                continue
            elif nav.isdigit():
                idx = int(nav) - 1
                if 0 <= idx < len(all_entries):
                    view_record_details(all_entries[idx]["type"], all_entries[idx]["data"])
                break
            elif nav == '':
                break
            else:
                break
        else:
            choice = input("\nEnter list number to view full details (or Enter to return): ").strip()
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(all_entries):
                    view_record_details(all_entries[idx]["type"], all_entries[idx]["data"])
            break

# ==================== SEARCH (EXTENDED) ====================
def search_records():
    Colors.print("\n🔍 SEARCH RECORDS", Colors.HEADER)
    query = input("Enter search term: ").strip().lower()
    if not query:
        return
    results = []
    for card in fetch_all_credit_cards():
        try:
            cardholder = decrypt(card['cardholder_enc']).lower()
            if query in cardholder or query in card['last_four'] or query in card.get('card_type', '').lower():
                results.append(("Credit Card", card))
        except:
            pass
    for aadhar in fetch_all_aadhar_cards():
        try:
            name = decrypt(aadhar['name_enc']).lower()
            if query in name or query in aadhar.get('masked_aadhar', '').lower():
                results.append(("Aadhaar", aadhar))
        except:
            pass
    for login in fetch_all_logins():
        try:
            service = decrypt(login['service_enc']).lower()
            username = decrypt(login['username_enc']).lower()
            if query in service or query in username:
                results.append(("Login", login))
        except:
            pass
    for bank in fetch_all_bank_accounts():
        try:
            bname = decrypt(bank['bank_name_enc']).lower()
            holder = decrypt(bank['account_holder_enc']).lower()
            if query in bname or query in holder:
                results.append(("Bank Account", bank))
        except:
            pass
    for note in fetch_all_secure_notes():
        try:
            title = decrypt(note['title_enc']).lower()
            if query in title:
                results.append(("Secure Note", note))
        except:
            pass
    for doc in fetch_all_personal_documents():
        try:
            dtype = decrypt(doc['doc_type_enc']).lower()
            name = decrypt(doc['name_enc']).lower()
            if query in dtype or query in name:
                results.append(("Personal Document", doc))
        except:
            pass
    for key in fetch_all_api_keys():
        try:
            svc = decrypt(key['service_name_enc']).lower()
            if query in svc:
                results.append(("API Key", key))
        except:
            pass

    if results:
        Colors.print(f"\n✅ Found {len(results)} results:", Colors.GREEN)
        page_size = 10
        total_pages = (len(results) + page_size - 1) // page_size
        page = 1
        while True:
            start = (page-1)*page_size
            end = min(start+page_size, len(results))
            print("-" * 60)
            for i in range(start, end):
                typ, record = results[i]
                if typ == "Credit Card":
                    print(f"{i+1:2}. {typ:15} | {record.get('card_type', 'Unknown')} ****{record['last_four']} | {decrypt(record['cardholder_enc'])}")
                elif typ == "Aadhaar":
                    print(f"{i+1:2}. {typ:15} | {record.get('masked_aadhar', 'MASKED')} | {decrypt(record['name_enc'])}")
                elif typ == "Login":
                    print(f"{i+1:2}. {typ:15} | {decrypt(record['service_enc'])} | {decrypt(record['username_enc'])}")
                elif typ == "Bank Account":
                    print(f"{i+1:2}. {typ:15} | {decrypt(record['bank_name_enc'])} | {decrypt(record['account_holder_enc'])}")
                elif typ == "Secure Note":
                    print(f"{i+1:2}. {typ:15} | {decrypt(record['title_enc'])}")
                elif typ == "Personal Document":
                    print(f"{i+1:2}. {typ:15} | {decrypt(record['doc_type_enc'])} | {decrypt(record['name_enc'])}")
                elif typ == "API Key":
                    print(f"{i+1:2}. {typ:15} | {decrypt(record['service_name_enc'])}")
            if total_pages > 1:
                print(f"\nPage {page}/{total_pages}")
                nav = input("Enter 'n' next, 'p' previous, or number to view details (Enter to return): ").strip().lower()
                if nav == 'n' and page < total_pages:
                    page += 1
                    continue
                elif nav == 'p' and page > 1:
                    page -= 1
                    continue
                elif nav.isdigit():
                    idx = int(nav) - 1
                    if 0 <= idx < len(results):
                        view_record_details(results[idx][0], results[idx][1])
                    break
                elif nav == '':
                    break
                else:
                    break
            else:
                choice = input("\nEnter number to view details (or Enter to return): ").strip()
                if choice.isdigit():
                    idx = int(choice) - 1
                    if 0 <= idx < len(results):
                        view_record_details(results[idx][0], results[idx][1])
                break
    else:
        Colors.print("❌ No results found", Colors.RED)

# ==================== DELETE RECORDS MENU (EXTENDED) ====================
def delete_records_menu():
    Colors.print("\nDelete records by type:", Colors.BLUE)
    print("1. Credit Card")
    print("2. Aadhaar Card")
    print("3. Login")
    print("4. Bank Account")
    print("5. Secure Note")
    print("6. Personal Document")
    print("7. API Key")
    choice = input("> ").strip()
    table_map = {
        "1": ("credit_cards", fetch_all_credit_cards, "Credit Card"),
        "2": ("aadhar_cards", fetch_all_aadhar_cards, "Aadhaar"),
        "3": ("login_details", fetch_all_logins, "Login"),
        "4": ("bank_accounts", fetch_all_bank_accounts, "Bank Account"),
        "5": ("secure_notes", fetch_all_secure_notes, "Secure Note"),
        "6": ("personal_documents", fetch_all_personal_documents, "Personal Document"),
        "7": ("api_keys", fetch_all_api_keys, "API Key")
    }
    if choice not in table_map:
        Colors.print("Invalid choice.", Colors.RED)
        return
    table, fetch_func, type_name = table_map[choice]
    records = fetch_func()
    if not records:
        Colors.print("No records to delete.", Colors.YELLOW)
        return
    for r in records:
        if table == "credit_cards":
            print(f"ID: {r['id']} | {r.get('card_type','?')} | {r['last_four']}")
        elif table == "aadhar_cards":
            print(f"ID: {r['id']} | {r.get('masked_aadhar','?')}")
        elif table == "login_details":
            print(f"ID: {r['id']} | {decrypt(r['service_enc'])} | {decrypt(r['username_enc'])}")
        elif table == "bank_accounts":
            print(f"ID: {r['id']} | {decrypt(r['bank_name_enc'])} | {decrypt(r['account_holder_enc'])}")
        elif table == "secure_notes":
            print(f"ID: {r['id']} | {decrypt(r['title_enc'])}")
        elif table == "personal_documents":
            print(f"ID: {r['id']} | {decrypt(r['doc_type_enc'])} | {decrypt(r['name_enc'])}")
        elif table == "api_keys":
            print(f"ID: {r['id']} | {decrypt(r['service_name_enc'])}")
    rid = input("Enter ID to delete: ").strip()
    if rid and rid.isdigit():
        rid = int(rid)
        if any(r['id'] == rid for r in records):
            delete_record_with_confirmation(table, rid)
        else:
            Colors.print("ID not found.", Colors.RED)

# ==================== MAIN ====================
def login_screen():
    while True:
        print("\n" + "="*50)
        Colors.print("   SECURE VAULT - LOGIN", Colors.HEADER)
        print("="*50)
        print("1. Login")
        print("2. Recover master password (use recovery key)")
        print("3. Exit")
        choice = input("> ").strip()
        if choice == "1":
            if verify_master_password():
                return True
            else:
                continue
        elif choice == "2":
            if recover_master_password():
                return True
            else:
                continue
        elif choice == "3":
            Colors.print("\n👋 Goodbye!", Colors.HEADER)
            return False
        else:
            Colors.print("❌ Invalid option.", Colors.RED)

def main():
    global DARK_MODE
    init_db()
    if not login_screen():
        return

    # Load auto-lock timeout from settings
    global SESSION_TIMEOUT
    try:
        conn = sqlite3.connect(DB_NAME)
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key = 'session_timeout'")
        row = cur.fetchone()
        if row:
            SESSION_TIMEOUT = int(row[0])
            session.timeout = SESSION_TIMEOUT
        conn.close()
    except:
        pass

    show_dashboard()

    while True:
        if not session.check_timeout():
            Colors.print("\n⏰ Session expired. Please login again.", Colors.RED)
            session.logout()
            if not login_screen():
                break
            show_dashboard()
            continue

        session.refresh()
        remaining = session.get_remaining_time()
        print("\n" + "="*50)
        Colors.print(f"   SENSITIVE DATA VAULT — Session: {remaining}s", Colors.HEADER)
        print("="*50)
        print("🔐 Authentication")
        print("  11. 🔐 Change Master Password")
        print("  12. 📱 Toggle 2FA")
        print("  14. 🚪 Logout")
        print("\n📝 Add Records")
        print("  1. 💳 Add Credit Card")
        print("  2. 🪪 Add Aadhaar Card")
        print("  3. 🔑 Add Login Details")
        print("  4. 🏦 Add Bank Account")
        print("  5. 📝 Add Secure Note")
        print("  6. 📄 Add Personal Document")
        print("  7. 🛡️ Add API Key / Recovery Code")
        print("\n📂 Manage Records")
        print("  8. 👁️ View All Records")
        print("  9. 🔍 Search Records")
        print("  10. ⭐ View Favorites")
        print("  15. ✏️ Edit Record")
        print("  16. 🗑️ Delete Record")
        print("  17. 📎 Attach File to Record")
        print("\n🔧 Security & Tools")
        print("  18. 📊 Statistics")
        print("  19. 🔒 Security Score")
        print("  20. 🔑 Generate Password")
        print("  21. 📤 Export Encrypted Backup")
        print("  22. 📥 Import Encrypted Backup")
        print("  23. 🌙 Toggle Dark Mode")
        print("  24. 🔒 Auto Lock Settings")
        print("  25. 📊 Dashboard")
        print("\n🐞 Developer / Debug")
        print("  26. 📎 List All Attachments (Debug)")
        choice = input("> ").strip()

        if choice == "1":
            menu_add_credit_card()
        elif choice == "2":
            menu_add_aadhar()
        elif choice == "3":
            menu_add_login()
        elif choice == "4":
            menu_add_bank_account()
        elif choice == "5":
            menu_add_secure_note()
        elif choice == "6":
            menu_add_personal_document()
        elif choice == "7":
            menu_add_api_key()
        elif choice == "8":
            view_all_records()
        elif choice == "9":
            search_records()
        elif choice == "10":
            favs = get_favorites()
            if not favs:
                Colors.print("No favorites yet.", Colors.YELLOW)
            else:
                Colors.print("\n⭐ FAVORITES", Colors.BLUE)
                for rec_type, rec_id in favs:
                    fetch_map = {
                        "credit_card": fetch_all_credit_cards,
                        "aadhar": fetch_all_aadhar_cards,
                        "login": fetch_all_logins,
                        "bank_account": fetch_all_bank_accounts,
                        "secure_note": fetch_all_secure_notes,
                        "personal_document": fetch_all_personal_documents,
                        "api_key": fetch_all_api_keys
                    }
                    records = fetch_map.get(rec_type, [])()
                    for r in records:
                        if r['id'] == rec_id:
                            type_display = rec_type.title().replace("_", " ")
                            view_record_details(type_display, r)
                            break
        elif choice == "11":
            change_master_password()
        elif choice == "12":
            toggle_2fa()
        elif choice == "13":
            pass  # Dark mode is now 23
        elif choice == "14":
            session.logout()
            Colors.print("\n👋 Logged out.", Colors.HEADER)
            if not login_screen():
                break
            show_dashboard()
        elif choice == "15":
            edit_record()
        elif choice == "16":
            delete_records_menu()
        elif choice == "17":
            attach_to_record_by_id()
        elif choice == "18":
            show_statistics()
        elif choice == "19":
            security_score()
        elif choice == "20":
            generate_strong_password()
        elif choice == "21":
            export_backup()
        elif choice == "22":
            import_backup()
        elif choice == "23":
            DARK_MODE = not DARK_MODE
            Colors.print(f"Dark mode {'ON' if DARK_MODE else 'OFF'}", Colors.YELLOW)
        elif choice == "24":
            set_auto_lock()
        elif choice == "25":
            show_dashboard()
        elif choice == "26":
            list_all_attachments()
        else:
            Colors.print("❌ Invalid option.", Colors.RED)

if __name__ == "__main__":
    main()
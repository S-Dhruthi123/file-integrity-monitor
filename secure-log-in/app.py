import sqlite3
import bcrypt
import time
import re
from datetime import datetime, timedelta
import os

DB = "users.db"
MAX_ATTEMPTS = 5
LOCK_TIME = 5 * 60  # 5 minutes in seconds

# --- Database setup with parameterized queries (SQL injection safe) ---
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, 
                  password_hash TEXT NOT NULL,
                  failed_attempts INTEGER DEFAULT 0,
                  lock_until REAL DEFAULT 0)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (timestamp TEXT, username TEXT, status TEXT, ip TEXT)''')
    conn.commit()
    conn.close()

def log_attempt(username, status):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    # Parameterized query - SAFE
    c.execute("INSERT INTO logs VALUES (?, ?, ?, ?)", 
              (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username, status, "127.0.0.1"))
    conn.commit()
    conn.close()

# --- Password Policy ---
def is_strong_password(pw):
    if len(pw) < 8:
        return False, "Min 8 characters required"
    if not re.search(r"[A-Za-z]", pw):
        return False, "Need at least one letter"
    if not re.search(r"[0-9]", pw):
        return False, "Need at least one number"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", pw):
        return False, "Need at least one symbol"
    return True, "OK"

# --- Signup ---
def signup():
    username = input("Enter new username: ").strip()
    password = input("Enter new password: ").strip()

    valid, msg = is_strong_password(password)
    if not valid:
        print(f"[!] Weak password: {msg}")
        return

    # Hash + Salt with bcrypt
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        # Parameterized query - SQL Injection Safe
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", 
                  (username, hashed.decode()))
        conn.commit()
        conn.close()
        print(f"[+] User {username} registered successfully!")
        print(f"[+] Hashed password stored: {hashed.decode()[:20]}... (not plain text)")
    except sqlite3.IntegrityError:
        print("[!] Username already exists")

# --- Login with Brute-force protection ---
def login():
    username = input("Username: ").strip()
    password = input("Password: ").strip()

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT password_hash, failed_attempts, lock_until FROM users WHERE username = ?", (username,))
    row = c.fetchone()

    # Safe error message - never reveal if user exists
    if not row:
        print("[!] Invalid username or password")
        log_attempt(username, "FAILED - user not found")
        conn.close()
        return

    stored_hash, failed_attempts, lock_until = row

    # Check lockout
    if time.time() < lock_until:
        remaining = int(lock_until - time.time())
        print(f"[!] Account locked. Try again after {remaining//60}m {remaining%60}s")
        log_attempt(username, "FAILED - account locked")
        conn.close()
        return

    # Check password
    if bcrypt.checkpw(password.encode(), stored_hash.encode()):
        # Success - reset counter
        c.execute("UPDATE users SET failed_attempts=0, lock_until=0 WHERE username=?", (username,))
        conn.commit()
        print(f"[OK] Login successful! Welcome {username}")
        log_attempt(username, "SUCCESS")
        # BONUS: Session token
        print(f"[BONUS] Session Token: SESSION-{os.urandom(8).hex()}")
    else:
        failed_attempts += 1
        if failed_attempts >= MAX_ATTEMPTS:
            lock_until = time.time() + LOCK_TIME
            c.execute("UPDATE users SET failed_attempts=?, lock_until=? WHERE username=?",
                      (failed_attempts, lock_until, username))
            print(f"[!] Too many failed attempts. Account locked for 5 minutes.")
            log_attempt(username, f"FAILED - locked after {failed_attempts} attempts")
        else:
            c.execute("UPDATE users SET failed_attempts=? WHERE username=?", (failed_attempts, username))
            print(f"[!] Invalid username or password (Attempt {failed_attempts}/{MAX_ATTEMPTS})")
            log_attempt(username, "FAILED - wrong password")
        conn.commit()
    conn.close()

def show_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT username, password_hash FROM users")
    print("\n--- DATABASE CONTENT (Hashed passwords) ---")
    for u, h in c.fetchall():
        print(f"User: {u} | Hash: {h}")
    print("-------------------------------------------\n")
    conn.close()

if __name__ == "__main__":
    init_db()
    while True:
        print("\n1. Signup  2. Login  3. Show DB (for demo)  4. Show Logs  5. Exit")
        ch = input("> ").strip()
        if ch == '1': signup()
        elif ch == '2': login()
        elif ch == '3': show_db()
        elif ch == '4':
            conn = sqlite3.connect(DB)
            c = conn.cursor()
            c.execute("SELECT * FROM logs")
            for r in c.fetchall(): print(r)
            conn.close()
        elif ch == '5': break

"""
MiniBank (Fixed) - Security-hardened version of the banking CLI.
All Bandit findings and intentional weaknesses have been resolved.
"""

import json
import os
import hashlib
import hmac
import secrets
import datetime
import sys
import re

# ============================================================
# FIX #4: Remove hardcoded secret — load from environment
#          variable, fall back to a generated per-run secret
#          (in production this must be set in the environment).
# ============================================================
SECRET_KEY = os.environ.get("MINIBANK_SECRET_KEY", secrets.token_hex(32))
USERS_FILE = "users_fixed.json"
SESSION_TOKEN = None
CURRENT_USER = None

# bcrypt is preferred; fall back to PBKDF2-HMAC-SHA256 if unavailable
try:
    import bcrypt
    USE_BCRYPT = True
except ImportError:
    USE_BCRYPT = False


# ============================================================
# Utility Functions
# ============================================================

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            content = f.read()
        return json.loads(content) if content.strip() else {}
    except (json.JSONDecodeError, ValueError):
        return {}


def save_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)


# ============================================================
# FIX #1: Replace MD5 with bcrypt (or PBKDF2-HMAC-SHA256)
# ============================================================

def hash_password(password: str) -> str:
    if USE_BCRYPT:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    # PBKDF2-HMAC-SHA256 with a random salt
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return f"{salt}${dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    if USE_BCRYPT:
        # Detect bcrypt hashes (start with $2b$)
        if stored_hash.startswith("$2"):
            return bcrypt.checkpw(password.encode(), stored_hash.encode())
    # PBKDF2 path
    if "$" in stored_hash:
        salt, dk_hex = stored_hash.split("$", 1)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
        return hmac.compare_digest(dk.hex(), dk_hex)
    return False


def generate_token(username: str) -> str:
    """Generate a cryptographically secure session token."""
    return secrets.token_urlsafe(32)


# ============================================================
# FIX #2: Sanitize inputs before logging to prevent log injection
# ============================================================

def sanitize_for_log(value: str) -> str:
    """Strip newlines/tabs (log injection) and replace non-ASCII chars for safe printing."""
    if not isinstance(value, str):
        value = str(value)
    # Strip control characters that enable log injection
    value = re.sub(r"[\r\n\t]", "_", value)
    # FIX #5 (fuzzer finding F-3): Replace non-ASCII to prevent UnicodeEncodeError
    # on Windows terminals that use narrow encodings (e.g., cp1252).
    # The raw value is still stored UTF-8 in the JSON data file.
    return value.encode("ascii", errors="replace").decode("ascii")


def log_event(username, action, amount=None):
    timestamp = datetime.datetime.now().isoformat()
    safe_username = sanitize_for_log(username)
    safe_action = sanitize_for_log(action)
    if amount is not None:
        safe_amount = sanitize_for_log(str(amount))
        msg = f"[{timestamp}] USER={safe_username} ACTION={safe_action} AMOUNT={safe_amount}"
    else:
        msg = f"[{timestamp}] USER={safe_username} ACTION={safe_action}"
    # Use errors='replace' so Unicode usernames never crash the stdout write on Windows
    try:
        print(f"LOG: {msg}")
    except UnicodeEncodeError:
        print("LOG: [message contained unencodable characters]")
    with open("bank_fixed.log", "a", encoding="utf-8") as log_file:
        log_file.write(msg + "\n")


# ============================================================
# FIX #3: Input validation helper
# ============================================================

def validate_amount(amount) -> tuple[bool, str]:
    """Return (valid, error_message). Amount must be a positive finite number."""
    try:
        value = float(amount)
    except (TypeError, ValueError):
        return False, "Amount must be a number."
    if value <= 0:
        return False, "Amount must be greater than zero."
    if value != value:          # NaN check
        return False, "Amount must be a valid number."
    if value == float("inf"):
        return False, "Amount must be a finite number."
    return True, ""


# ============================================================
# Account Operations
# ============================================================

def register(username: str, password: str) -> bool:
    if not username or not password:
        print("Error: Username and password cannot be empty.")
        return False
    users = load_users()
    if username in users:
        print("Error: Username already exists.")
        return False
    users[username] = {
        "password_hash": hash_password(password),
        "balance": 0.0,
        "failed_attempts": 0,
        "locked": False,
        "transactions": []
    }
    save_users(users)
    print(f"User '{sanitize_for_log(username)}' registered successfully.")
    log_event(username, "REGISTER")
    return True


def login(username: str, password: str) -> bool:
    global SESSION_TOKEN, CURRENT_USER
    users = load_users()

    if username not in users:
        print("Error: User not found.")
        return False

    user = users[username]

    if user["locked"]:
        print("Error: Account is locked due to too many failed login attempts.")
        return False

    if not verify_password(password, user["password_hash"]):
        user["failed_attempts"] += 1
        if user["failed_attempts"] >= 3:
            user["locked"] = True
            save_users(users)
            print("Error: Too many failed attempts. Account locked.")
            log_event(username, "ACCOUNT_LOCKED")
        else:
            save_users(users)
            remaining = 3 - user["failed_attempts"]
            print(f"Error: Incorrect password. {remaining} attempt(s) remaining.")
        return False

    user["failed_attempts"] = 0
    save_users(users)
    SESSION_TOKEN = generate_token(username)
    CURRENT_USER = username
    print(f"Login successful. Welcome, {sanitize_for_log(username)}!")
    log_event(username, "LOGIN")
    return True


def deposit(username: str, amount) -> bool:
    # FIX #3: Validate amount before processing
    valid, err = validate_amount(amount)
    if not valid:
        print(f"Error: {err}")
        return False

    amount = float(amount)
    users = load_users()
    if username not in users:
        print("Error: User not found.")
        return False

    users[username]["balance"] += amount
    tx = {
        "type": "deposit",
        "amount": amount,
        "timestamp": datetime.datetime.now().isoformat(),
        "balance_after": users[username]["balance"]
    }
    users[username]["transactions"].append(tx)
    save_users(users)
    print(f"Deposited ${amount:.2f}. New balance: ${users[username]['balance']:.2f}")
    log_event(username, "DEPOSIT", amount)
    return True


def withdraw(username: str, amount) -> bool:
    # FIX #3: Validate amount before processing
    valid, err = validate_amount(amount)
    if not valid:
        print(f"Error: {err}")
        return False

    amount = float(amount)
    users = load_users()
    if username not in users:
        print("Error: User not found.")
        return False

    balance = users[username]["balance"]
    if amount > balance:
        print(f"Error: Insufficient funds. Balance: ${balance:.2f}")
        return False

    users[username]["balance"] -= amount
    tx = {
        "type": "withdrawal",
        "amount": amount,
        "timestamp": datetime.datetime.now().isoformat(),
        "balance_after": users[username]["balance"]
    }
    users[username]["transactions"].append(tx)
    save_users(users)
    print(f"Withdrew ${amount:.2f}. New balance: ${users[username]['balance']:.2f}")
    log_event(username, "WITHDRAW", amount)
    return True


def transfer(sender: str, recipient: str, amount) -> bool:
    valid, err = validate_amount(amount)
    if not valid:
        print(f"Error: {err}")
        return False

    amount = float(amount)
    users = load_users()

    if recipient not in users:
        print(f"Error: Recipient '{sanitize_for_log(recipient)}' not found.")
        return False
    if sender not in users:
        print("Error: Sender account not found.")
        return False

    sender_balance = users[sender]["balance"]
    if amount > sender_balance:
        print(f"Error: Insufficient funds. Balance: ${sender_balance:.2f}")
        return False

    users[sender]["balance"] -= amount
    users[recipient]["balance"] += amount

    timestamp = datetime.datetime.now().isoformat()
    users[sender]["transactions"].append({
        "type": "transfer_out",
        "amount": amount,
        "to": recipient,
        "timestamp": timestamp,
        "balance_after": users[sender]["balance"]
    })
    users[recipient]["transactions"].append({
        "type": "transfer_in",
        "amount": amount,
        "from": sender,
        "timestamp": timestamp,
        "balance_after": users[recipient]["balance"]
    })
    save_users(users)
    print(f"Transferred ${amount:.2f} to '{sanitize_for_log(recipient)}'. "
          f"New balance: ${users[sender]['balance']:.2f}")
    log_event(sender, "TRANSFER_OUT", amount)
    log_event(recipient, "TRANSFER_IN", amount)
    return True


def view_history(username: str):
    users = load_users()
    if username not in users:
        print("Error: User not found.")
        return
    transactions = users[username]["transactions"]
    if not transactions:
        print("No transactions found.")
        return
    print(f"\n--- Transaction History for {sanitize_for_log(username)} ---")
    for i, tx in enumerate(transactions, 1):
        print(f"{i}. [{tx['timestamp']}] {tx['type'].upper()} "
              f"${tx['amount']:.2f} | Balance after: ${tx['balance_after']:.2f}")
    print("-------------------------------------------\n")


# ============================================================
# CLI Interface
# ============================================================

def main():
    global CURRENT_USER, SESSION_TOKEN
    print("=" * 40)
    print("    Welcome to MiniBank CLI (Secured)")
    print("=" * 40)

    while True:
        if CURRENT_USER is None:
            print("\n[1] Register  [2] Login  [3] Quit")
            choice = input("Choose: ").strip()

            if choice == "1":
                uname = input("Username: ").strip()
                pwd = input("Password: ").strip()
                register(uname, pwd)

            elif choice == "2":
                uname = input("Username: ").strip()
                pwd = input("Password: ").strip()
                login(uname, pwd)

            elif choice == "3":
                print("Goodbye!")
                sys.exit(0)

            else:
                print("Invalid choice.")

        else:
            print(f"\nLogged in as: {CURRENT_USER}")
            print("[1] Deposit  [2] Withdraw  [3] Transfer  [4] History  [5] Logout")
            choice = input("Choose: ").strip()

            if choice == "1":
                amt = input("Amount: ").strip()
                deposit(CURRENT_USER, amt)

            elif choice == "2":
                amt = input("Amount: ").strip()
                withdraw(CURRENT_USER, amt)

            elif choice == "3":
                recipient = input("Recipient username: ").strip()
                amt = input("Amount: ").strip()
                transfer(CURRENT_USER, recipient, amt)

            elif choice == "4":
                view_history(CURRENT_USER)

            elif choice == "5":
                print(f"Logged out {CURRENT_USER}.")
                log_event(CURRENT_USER, "LOGOUT")
                CURRENT_USER = None
                SESSION_TOKEN = None

            else:
                print("Invalid choice.")


if __name__ == "__main__":
    main()

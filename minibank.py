"""
MiniBank - A Python CLI Banking Application
Intentionally contains security weaknesses for educational analysis.
"""

import json
import os
import hashlib
import datetime
import sys

# ============================================================
# SECURITY WEAKNESS #4: Hardcoded secret key
# ============================================================
SECRET_KEY = "hardcoded_secret_key_12345"
USERS_FILE = "users.json"
SESSION_TOKEN = None
CURRENT_USER = None

# ============================================================
# Utility Functions
# ============================================================

def load_users():
    """Load users from the JSON file."""
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)


def save_users(users):
    """Save users to the JSON file."""
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def hash_password(password):
    # ============================================================
    # SECURITY WEAKNESS #1: MD5 is a weak hashing algorithm
    # ============================================================
    return hashlib.md5(password.encode()).hexdigest()


def generate_token(username):
    # Uses hardcoded secret — predictable and insecure
    raw = f"{username}:{SECRET_KEY}"
    return hashlib.md5(raw.encode()).hexdigest()


def log_event(username, action, amount=None):
    # ============================================================
    # SECURITY WEAKNESS #2: Log injection via unsanitized input
    # ============================================================
    timestamp = datetime.datetime.now().isoformat()
    if amount is not None:
        # Vulnerable: username and amount are not sanitized
        msg = f"[{timestamp}] USER={username} ACTION={action} AMOUNT={amount}"
    else:
        msg = f"[{timestamp}] USER={username} ACTION={action}"
    print(f"LOG: {msg}")
    # In a real system this would write to a log file — injection is possible
    with open("bank.log", "a") as log_file:
        log_file.write(msg + "\n")


# ============================================================
# Account Operations
# ============================================================

def register(username, password):
    """Register a new user."""
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
    print(f"User '{username}' registered successfully.")
    log_event(username, "REGISTER")
    return True


def login(username, password):
    """Login a user. Locks account after 3 failed attempts."""
    global SESSION_TOKEN, CURRENT_USER
    users = load_users()

    if username not in users:
        print("Error: User not found.")
        return False

    user = users[username]

    if user["locked"]:
        print("Error: Account is locked due to too many failed login attempts.")
        return False

    if user["password_hash"] != hash_password(password):
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

    # Successful login — reset failed attempts
    user["failed_attempts"] = 0
    save_users(users)
    SESSION_TOKEN = generate_token(username)
    CURRENT_USER = username
    print(f"Login successful. Welcome, {username}!")
    log_event(username, "LOGIN")
    return True


def deposit(username, amount):
    """Deposit money into account."""
    # ============================================================
    # SECURITY WEAKNESS #3: No input validation on amounts
    # Negative deposits effectively act as withdrawals
    # ============================================================
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


def withdraw(username, amount):
    """Withdraw money from account."""
    # ============================================================
    # SECURITY WEAKNESS #3 (continued): No validation — negative
    # amounts allowed, balance can go negative (overdraft exploit)
    # ============================================================
    users = load_users()
    if username not in users:
        print("Error: User not found.")
        return False

    balance = users[username]["balance"]
    if balance < amount:
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


def transfer(sender, recipient, amount):
    """Transfer money between accounts."""
    users = load_users()
    if recipient not in users:
        print(f"Error: Recipient '{recipient}' not found.")
        return False
    if sender not in users:
        print("Error: Sender account not found.")
        return False

    sender_balance = users[sender]["balance"]
    if sender_balance < amount:
        print(f"Error: Insufficient funds. Balance: ${sender_balance:.2f}")
        return False

    # No validation on amount — negative transfers steal from recipient
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
    print(f"Transferred ${amount:.2f} to '{recipient}'. New balance: ${users[sender]['balance']:.2f}")
    log_event(sender, "TRANSFER_OUT", amount)
    log_event(recipient, "TRANSFER_IN", amount)
    return True


def view_history(username):
    """View transaction history."""
    users = load_users()
    if username not in users:
        print("Error: User not found.")
        return
    transactions = users[username]["transactions"]
    if not transactions:
        print("No transactions found.")
        return
    print(f"\n--- Transaction History for {username} ---")
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
    print("       Welcome to MiniBank CLI")
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
                amt = float(input("Amount: ").strip())
                deposit(CURRENT_USER, amt)

            elif choice == "2":
                amt = float(input("Amount: ").strip())
                withdraw(CURRENT_USER, amt)

            elif choice == "3":
                recipient = input("Recipient username: ").strip()
                amt = float(input("Amount: ").strip())
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

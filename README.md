# MiniBank CLI

A Python command-line banking application built for a Software Security Engineering course. The repository contains two versions of the application — an intentionally vulnerable original (`minibank.py`) and a security-hardened replacement (`minibank_fixed.py`) — together with a full security analysis covering static analysis, black-box testing, fuzzing, and formal verification.

---

## Table of Contents

- [Features](#features)
- [Repository Layout](#repository-layout)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Using the CLI](#using-the-cli)
- [Configuration](#configuration)
- [Running the Tests](#running-the-tests)
- [Running the Fuzzer](#running-the-fuzzer)
- [Security Notes](#security-notes)
- [Project Files](#project-files)

---

## Features

| Feature | Description |
|---------|-------------|
| Register | Create a new account; password is hashed before storage |
| Login | Authenticate with username and password; account locks after 3 failed attempts |
| Deposit | Credit a positive amount to your balance |
| Withdraw | Debit a positive amount; rejects overdrafts |
| Transfer | Move funds to another registered account |
| History | View a timestamped ledger of all your transactions |
| Audit log | Every operation is appended to `bank_fixed.log` |

---

## Repository Layout

```
sse_final_project/
├── minibank.py            # Original app — intentionally vulnerable (educational)
├── minibank_fixed.py      # Hardened app — all vulnerabilities resolved
├── test_minibank.py       # 5 pytest black-box test cases (TC-01 … TC-05)
├── fuzz_minibank.py       # Pure-Python genetic algorithm fuzzer (10 000 iterations)
├── auth_model.pml         # Promela model for SPIN model checker
├── bandit_report.txt      # Bandit SAST output on the original version
├── bandit_report_fixed.txt# Bandit output on the fixed version (0 issues)
├── generate_report.py     # Script that produces security_report.docx
├── security_report.docx   # Full academic security analysis report
└── README.md              # This file
```

---

## Requirements

- Python 3.10 or later
- `bcrypt` (recommended; falls back to PBKDF2-HMAC-SHA256 if absent)

Install all dependencies at once:

```bash
pip install bcrypt pytest bandit
```

> `bcrypt` is optional but strongly recommended. Without it the fixed version
> uses PBKDF2-HMAC-SHA256 with 260 000 iterations, which is still secure but
> slower on login/register.

---

## Quick Start

**Use the hardened version** (`minibank_fixed.py`) for all normal use:

```bash
python minibank_fixed.py
```

You will see the main menu:

```
========================================
    Welcome to MiniBank CLI (Secured)
========================================

[1] Register  [2] Login  [3] Quit
Choose:
```

> **Do not use `minibank.py` in any real or shared environment.** It stores
> passwords as MD5 hashes, has a hardcoded secret key, and performs no input
> validation. It exists solely as a teaching artefact for the security analysis.

---

## Using the CLI

### Register a new account

```
Choose: 1
Username: alice
Password: my_secure_password
→ User 'alice' registered successfully.
```

### Log in

```
Choose: 2
Username: alice
Password: my_secure_password
→ Login successful. Welcome, alice!
```

### Deposit funds

```
Logged in as: alice
Choose: 1
Amount: 500
→ Deposited $500.00. New balance: $500.00
```

### Withdraw funds

```
Choose: 2
Amount: 200
→ Withdrew $200.00. New balance: $300.00
```

Attempting to withdraw more than your balance:

```
Amount: 9999
→ Error: Insufficient funds. Balance: $300.00
```

### Transfer to another account

```
Choose: 3
Recipient username: bob
Amount: 50
→ Transferred $50.00 to 'bob'. New balance: $250.00
```

Transferring to a user that does not exist:

```
Recipient username: nobody
→ Error: Recipient 'nobody' not found.
```

### View transaction history

```
Choose: 4
--- Transaction History for alice ---
1. [2026-04-16T10:00:00] DEPOSIT $500.00 | Balance after: $500.00
2. [2026-04-16T10:01:00] WITHDRAWAL $200.00 | Balance after: $300.00
3. [2026-04-16T10:02:00] TRANSFER_OUT $50.00 | Balance after: $250.00
-------------------------------------
```

### Log out

```
Choose: 5
→ Logged out alice.
```

### Account lockout

After **3 consecutive wrong passwords** the account is locked:

```
Error: Incorrect password. 2 attempt(s) remaining.
Error: Incorrect password. 1 attempt(s) remaining.
Error: Too many failed attempts. Account locked.
```

Subsequent login attempts — even with the correct password — are rejected until an administrator manually resets the `locked` flag in `users_fixed.json`.

---

## Configuration

### Secret key

The session token is derived using a cryptographically secure random key. Set
the `MINIBANK_SECRET_KEY` environment variable to pin the key across restarts:

```bash
# Linux / macOS
export MINIBANK_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"

# Windows PowerShell
$env:MINIBANK_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
```

If the variable is not set, a new random key is generated each run (sessions
do not persist across restarts, which is acceptable for a CLI application).

### Data files

| File | Purpose |
|------|---------|
| `users_fixed.json` | User accounts, hashed passwords, balances, transaction history |
| `bank_fixed.log` | Append-only audit log of every operation |

Both files are created automatically on first run in the current working directory.

---

## Running the Tests

```bash
pip install pytest bcrypt
pytest test_minibank.py -v
```

Expected output:

```
test_minibank.py::test_tc01_login_wrong_password          PASSED
test_minibank.py::test_tc02_withdraw_overdraft            PASSED
test_minibank.py::test_tc03_deposit_negative_amount       PASSED
test_minibank.py::test_tc04_account_lockout               PASSED
test_minibank.py::test_tc05_transfer_nonexistent_recipient PASSED

5 passed in ~2s
```

| ID | What is tested |
|----|----------------|
| TC-01 | Wrong password → graceful failure, no crash |
| TC-02 | Withdraw > balance → overdraft rejected |
| TC-03 | Deposit negative amount → rejected |
| TC-04 | 3 failed logins → account locked |
| TC-05 | Transfer to nonexistent user → error, balance unchanged |

---

## Running the Fuzzer

The fuzzer targets `minibank_fixed.py` and exercises `login`, `deposit`,
`withdraw`, and `transfer` with mutated strings and numeric edge cases
(NaN, ±Infinity, negative values, Unicode, injection payloads).

```bash
python fuzz_minibank.py
```

This runs **10 000 iterations** and writes a summary to `fuzz_report.txt`.
Expected result on the fixed version: **0 crashes**.

```
Starting fuzzer — 10000 iterations across 4 targets
  ... 1000/10000 iterations (0 crashes)
  ...
Fuzzing complete. Total iterations: 10000
Total crashes found: 0
Report written to fuzz_report.txt
```

---

## Security Notes

### What was fixed (`minibank.py` → `minibank_fixed.py`)

| # | Weakness | CWE | Fix |
|---|----------|-----|-----|
| 1 | MD5 password hashing | CWE-327 | bcrypt / PBKDF2-HMAC-SHA256 (260 000 rounds) |
| 2 | Log injection via unsanitised input | CWE-117 | `sanitize_for_log()` strips control chars and non-ASCII |
| 3 | No amount validation (negative amounts) | CWE-20 | `validate_amount()` enforces `amount > 0`, non-NaN, finite |
| 4 | Hardcoded secret key | CWE-259 | `os.environ.get("MINIBANK_SECRET_KEY", secrets.token_hex(32))` |
| 5 | File I/O without explicit encoding (fuzzer finding) | CWE-116 | All `open()` calls use `encoding="utf-8"` |

### Known remaining limitations

- `users_fixed.json` is **not encrypted at rest**. Anyone with filesystem access can read all balances. Encrypt the file or use a proper database with access controls in production.
- The account **lock is not rate-limit-hardened** at a system level. Restarting the process does not unlock accounts (the `locked` flag persists in the JSON file), but there is no exponential back-off on the registration endpoint.
- **No TLS / network layer** — MiniBank is a local CLI only. Do not expose it over a network without a proper transport security layer.

---

## Project Files

| File | Description |
|------|-------------|
| `security_report.docx` | 8-section academic report covering all four analysis methods |
| `bandit_report.txt` | Raw Bandit SAST output for the original version (3 findings) |
| `bandit_report_fixed.txt` | Bandit output for the fixed version (0 findings) |
| `auth_model.pml` | Promela FSM model; verifies two LTL safety properties with SPIN |
| `generate_report.py` | Regenerates `security_report.docx` from source (requires `python-docx`) |

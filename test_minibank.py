"""
Black-box test cases for MiniBank (minibank_fixed.py).
Each test uses the anatomy format required by the project.
"""

import pytest
import os
import json
import importlib.util
import sys

# ---------------------------------------------------------------------------
# Test Fixture Setup
# ---------------------------------------------------------------------------

USERS_FILE = "users_fixed.json"


def load_module(path="minibank_fixed.py"):
    """Dynamically import minibank_fixed so tests are isolated."""
    spec = importlib.util.spec_from_file_location("minibank_fixed", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(autouse=True)
def clean_users_file():
    """Remove the users file before and after every test for isolation."""
    if os.path.exists(USERS_FILE):
        os.remove(USERS_FILE)
    yield
    if os.path.exists(USERS_FILE):
        os.remove(USERS_FILE)
    # Clean up log file too
    if os.path.exists("bank_fixed.log"):
        os.remove("bank_fixed.log")


@pytest.fixture()
def mb():
    """Return a fresh minibank_fixed module instance."""
    return load_module()


# ---------------------------------------------------------------------------
# TEST CASE ID: TC-01
# Objective:     Verify that login with an incorrect password fails gracefully
#                (returns False and prints an error) without crashing.
# Preconditions: A registered user exists with a known correct password.
# Input data:    username="alice", password="wrong_password"
# Expected result: login() returns False; error message is printed;
#                  no exception is raised.
# Actual result: login() returned False with "Error: Incorrect password."
#                No exception raised.
# Pass/Fail:     PASS
# ---------------------------------------------------------------------------

def test_tc01_login_wrong_password(mb, capsys):
    """TC-01: Login with incorrect password fails gracefully."""
    mb.register("alice", "correct_password")
    result = mb.login("alice", "wrong_password")
    captured = capsys.readouterr()

    assert result is False, "login() should return False on wrong password"
    assert "incorrect password" in captured.out.lower() or \
           "error" in captured.out.lower(), \
        "An error message should be printed"


# ---------------------------------------------------------------------------
# TEST CASE ID: TC-02
# Objective:     Verify that withdrawing more than the account balance is
#                rejected (overdraft prevention).
# Preconditions: User "bob" is registered and has a balance of $50.00.
# Input data:    username="bob", amount=200.00
# Expected result: withdraw() returns False; "insufficient funds" error printed;
#                  balance remains $50.00.
# Actual result: withdraw() returned False with "Error: Insufficient funds."
#                Balance unchanged at $50.00.
# Pass/Fail:     PASS
# ---------------------------------------------------------------------------

def test_tc02_withdraw_overdraft(mb, capsys):
    """TC-02: Withdrawing more than balance is rejected."""
    mb.register("bob", "pass123")
    mb.deposit("bob", 50.0)
    capsys.readouterr()  # clear previous output

    result = mb.withdraw("bob", 200.0)
    captured = capsys.readouterr()

    assert result is False, "withdraw() should return False when amount > balance"
    assert "insufficient" in captured.out.lower(), \
        "Should print 'Insufficient funds' message"

    # Verify balance unchanged
    users = json.loads(open(USERS_FILE).read())
    assert users["bob"]["balance"] == 50.0, "Balance should not change after failed withdrawal"


# ---------------------------------------------------------------------------
# TEST CASE ID: TC-03
# Objective:     Verify that depositing a negative amount is rejected with
#                a clear error message (no silent balance corruption).
# Preconditions: User "carol" is registered with balance $0.00.
# Input data:    username="carol", amount=-100.00
# Expected result: deposit() returns False; error message printed;
#                  balance remains $0.00.
# Actual result: deposit() returned False with "Amount must be greater than zero."
#                Balance unchanged at $0.00.
# Pass/Fail:     PASS
# ---------------------------------------------------------------------------

def test_tc03_deposit_negative_amount(mb, capsys):
    """TC-03: Depositing a negative amount is rejected."""
    mb.register("carol", "pass123")
    capsys.readouterr()

    result = mb.deposit("carol", -100.0)
    captured = capsys.readouterr()

    assert result is False, "deposit() should return False for negative amount"
    assert "error" in captured.out.lower() or "zero" in captured.out.lower() \
           or "greater" in captured.out.lower(), \
        "Should print a meaningful error for negative deposit"

    users = json.loads(open(USERS_FILE).read())
    assert users["carol"]["balance"] == 0.0, "Balance must stay 0 after invalid deposit"


# ---------------------------------------------------------------------------
# TEST CASE ID: TC-04
# Objective:     Verify account lockout after exactly 3 consecutive failed
#                login attempts.
# Preconditions: User "dave" is registered with password "secret".
# Input data:    Three login attempts with password="wrongpass"
# Expected result: After the 3rd failure login() returns False and the account
#                  is marked locked; subsequent login with CORRECT password also
#                  fails because the account is locked.
# Actual result: Account locked after 3rd failure; correct password rejected with
#                "Account is locked" message.
# Pass/Fail:     PASS
# ---------------------------------------------------------------------------

def test_tc04_account_lockout(mb, capsys):
    """TC-04: Account locks after 3 consecutive failed login attempts."""
    mb.register("dave", "secret")
    capsys.readouterr()

    for _ in range(3):
        mb.login("dave", "wrongpass")

    captured = capsys.readouterr()
    assert "locked" in captured.out.lower(), \
        "Should indicate account locked after 3 failures"

    # Even the correct password should now be rejected
    result = mb.login("dave", "secret")
    captured = capsys.readouterr()
    assert result is False, "Locked account must not allow login even with correct password"
    assert "locked" in captured.out.lower(), \
        "Locked message should appear on subsequent login attempts"

    # Confirm locked flag in storage
    users = json.loads(open(USERS_FILE).read())
    assert users["dave"]["locked"] is True, "User's locked flag must be True in storage"


# ---------------------------------------------------------------------------
# TEST CASE ID: TC-05
# Objective:     Verify that transferring to a non-existent recipient returns
#                an error and does not crash or corrupt sender's balance.
# Preconditions: User "eve" is registered with balance $100.00.
#                No user "ghost" exists.
# Input data:    sender="eve", recipient="ghost", amount=50.00
# Expected result: transfer() returns False; error message printed;
#                  "eve"'s balance remains $100.00; no exception raised.
# Actual result: transfer() returned False with "Recipient 'ghost' not found."
#                Balance unchanged at $100.00.
# Pass/Fail:     PASS
# ---------------------------------------------------------------------------

def test_tc05_transfer_nonexistent_recipient(mb, capsys):
    """TC-05: Transfer to non-existent account returns error without crash."""
    mb.register("eve", "pass123")
    mb.deposit("eve", 100.0)
    capsys.readouterr()

    result = mb.transfer("eve", "ghost", 50.0)
    captured = capsys.readouterr()

    assert result is False, "transfer() should return False when recipient doesn't exist"
    assert "not found" in captured.out.lower() or "error" in captured.out.lower(), \
        "Should print a 'not found' or error message"

    users = json.loads(open(USERS_FILE).read())
    assert users["eve"]["balance"] == 100.0, "Sender balance must be unchanged"

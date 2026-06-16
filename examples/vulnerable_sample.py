"""
Intentionally vulnerable Python sample — FOR TESTING AND DEMO PURPOSES ONLY.

This file contains obvious security flaws used to verify that vulnhound's SAST
scanner detects common vulnerability patterns.  DO NOT use any of these patterns
in production code.
"""

import subprocess
import sqlite3

# ---------------------------------------------------------------------------
# VULNERABILITY 1: Hard-coded secret / password (CWE-798)
# ---------------------------------------------------------------------------
# BAD: embedding credentials directly in source code exposes them in version
# control and to anyone who can read the file.
DATABASE_PASSWORD = "SuperSecret123!"  # noqa: S105 – intentional vuln
API_SECRET_KEY = "hardcoded-api-key-do-not-use"  # noqa: S105


# ---------------------------------------------------------------------------
# VULNERABILITY 2: SQL Injection via string formatting (CWE-89)
# ---------------------------------------------------------------------------
def get_user(username: str) -> list:
    """Fetch a user row — VULNERABLE to SQL injection."""
    conn = sqlite3.connect("app.db")
    # BAD: user-supplied data interpolated directly into the query string.
    query = "SELECT * FROM users WHERE username = '%s'" % username  # noqa: S608
    cursor = conn.execute(query)
    return cursor.fetchall()


# ---------------------------------------------------------------------------
# VULNERABILITY 3: eval() on user-supplied input (CWE-95)
# ---------------------------------------------------------------------------
def calculate(expression: str):
    """Evaluate a math expression — VULNERABLE to arbitrary code execution."""
    # BAD: eval() executes arbitrary Python code supplied by the caller.
    return eval(expression)  # noqa: S307


# ---------------------------------------------------------------------------
# VULNERABILITY 4: subprocess with shell=True on user input (CWE-78)
# ---------------------------------------------------------------------------
def run_command(user_input: str) -> str:
    """Run a system command — VULNERABLE to OS command injection."""
    # BAD: passing user-controlled data to shell=True allows command injection.
    result = subprocess.run(  # noqa: S602
        f"echo {user_input}",
        shell=True,  # noqa: S602
        capture_output=True,
        text=True,
    )
    return result.stdout

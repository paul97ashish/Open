"""Dynamic Application Security Testing (DAST) module.

Performs authorized web testing: bounded same-origin crawls plus passive/active
security checks, optionally with LLM analysis. Must run OFFLINE in tests using
canned HTTP responses (no real network).

Authorization gate: requires ``config.authorized == True`` to prevent accidental
testing of unauthorized targets.
"""

__all__ = ["scanner"]

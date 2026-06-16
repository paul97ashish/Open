"""SAST (Static Application Security Testing) scan mode for vulnhound.

Walk a codebase, send numbered source to the LLM with a security-auditor
prompt, and return structured Finding objects.
"""

from vulnhound.sast.scanner import run

__all__ = ["run"]

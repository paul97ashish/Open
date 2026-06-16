"""Dependency scanning mode for vulnhound.

Parse manifest files (requirements.txt, package.json, go.mod, etc.), query OSV.dev
for known vulnerabilities, and return structured Finding objects.
"""

from vulnhound.deps.scanner import run

__all__ = ["run"]

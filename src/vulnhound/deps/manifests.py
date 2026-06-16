"""Parse dependency manifests (requirements.txt, package.json, go.mod, pom.xml, etc.)."""

from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class Dependency:
    """A single dependency extracted from a manifest."""

    ecosystem: str  # OSV ecosystem name: "PyPI", "npm", "Go", "Maven", "RubyGems"
    name: str
    version: str
    manifest: str  # path to the manifest file


# Directories to skip when walking the filesystem.
IGNORE_DIRS = {".git", "node_modules", "venv", ".venv", "env", ".env", "__pycache__",
               ".pytest_cache", ".tox", "dist", "build", ".eggs", "*.egg-info"}


def find_manifests(root: str) -> list[str]:
    """Walk root and find all supported manifest files.

    Returns a list of absolute paths to manifest files.
    """
    root = os.path.abspath(root)
    manifests = []

    # List of (filename_pattern, extension_pattern) tuples
    manifest_patterns = [
        ("requirements*.txt", None),
        ("Pipfile.lock", None),
        ("poetry.lock", None),
        ("package.json", None),
        ("package-lock.json", None),
        ("go.mod", None),
        ("pom.xml", None),
        ("Gemfile.lock", None),
    ]

    for dirpath, dirnames, filenames in os.walk(root):
        # Skip ignored directories
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]

        for filename in filenames:
            # Check if filename matches any pattern
            for pattern, _ in manifest_patterns:
                if pattern.startswith("requirements"):
                    # Handle wildcard pattern
                    if filename.startswith("requirements") and filename.endswith(".txt"):
                        manifests.append(os.path.join(dirpath, filename))
                        break
                elif filename == pattern:
                    manifests.append(os.path.join(dirpath, filename))
                    break

    return manifests


def parse_requirements_txt(path: str) -> list[Dependency]:
    """Parse a requirements.txt file (pragmatic: only `name==version` pinned deps)."""
    deps = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                # Skip comments and blank lines
                if not line or line.startswith("#"):
                    continue
                # Skip -r includes
                if line.startswith("-"):
                    continue
                # Skip lines with markers or extras (pragmatic approach)
                # Extract just the package==version part
                if ";" in line:
                    line = line.split(";")[0].strip()
                if "[" in line:
                    line = line.split("[")[0].strip()
                # Match name==version pattern
                match = re.match(r"^([a-zA-Z0-9._-]+)==([a-zA-Z0-9._+-]+)$", line.strip())
                if match:
                    name, version = match.groups()
                    deps.append(Dependency(
                        ecosystem="PyPI",
                        name=name,
                        version=version,
                        manifest=path
                    ))
    except (OSError, IOError):
        pass
    return deps


def parse_package_json(path: str) -> list[Dependency]:
    """Parse package.json for dependencies + devDependencies (npm ecosystem)."""
    deps = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, IOError, json.JSONDecodeError):
        return deps

    # Process dependencies and devDependencies
    for dep_type in ["dependencies", "devDependencies"]:
        dep_dict = data.get(dep_type, {})
        for name, version_spec in dep_dict.items():
            # Strip leading ^ and ~ from semver ranges; keep only concrete versions
            version = str(version_spec).lstrip("^~")
            # Further strip any whitespace or complex version specs
            version = version.split()[0] if version else ""
            if version:
                deps.append(Dependency(
                    ecosystem="npm",
                    name=name,
                    version=version,
                    manifest=path
                ))
    return deps


def parse_package_lock(path: str) -> list[Dependency]:
    """Parse package-lock.json for dependencies with concrete versions."""
    deps = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, IOError, json.JSONDecodeError):
        return deps

    # Walk the packages structure (present in lockfile v2+)
    packages = data.get("packages", {})
    dependencies = data.get("dependencies", {})

    # Try the new format first (packages object)
    for pkg_path, pkg_info in packages.items():
        if pkg_path == "" or "/" not in pkg_path:
            continue
        if not isinstance(pkg_info, dict):
            continue
        version = pkg_info.get("version", "")
        if version:
            # Extract package name from path (e.g., "node_modules/lodash" -> "lodash")
            parts = pkg_path.split("/")
            name = parts[-1] if parts[-1] else parts[-2] if len(parts) > 1 else ""
            if name and not name.startswith("."):
                deps.append(Dependency(
                    ecosystem="npm",
                    name=name,
                    version=version,
                    manifest=path
                ))

    # Fall back to dependencies object (older format)
    if not deps:
        for name, dep_info in dependencies.items():
            if isinstance(dep_info, dict):
                version = dep_info.get("version", "")
                if version:
                    deps.append(Dependency(
                        ecosystem="npm",
                        name=name,
                        version=version,
                        manifest=path
                    ))

    return deps


def parse_go_mod(path: str) -> list[Dependency]:
    """Parse go.mod for require blocks/lines (Go ecosystem)."""
    deps = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            content = fh.read()
    except (OSError, IOError):
        return deps

    # Match require blocks and single require lines
    # Format: go.mod uses "require (" blocks or individual "require" statements
    # Each dependency is like: github.com/some/module v1.2.3
    in_require = False
    for line in content.split("\n"):
        line = line.strip()
        if line.startswith("require"):
            if line == "require (":
                in_require = True
            else:
                # Single require line
                parts = line.replace("require", "").strip().split()
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1]
                    deps.append(Dependency(
                        ecosystem="Go",
                        name=name,
                        version=version,
                        manifest=path
                    ))
        elif in_require:
            if line == ")":
                in_require = False
            elif line and not line.startswith("//"):
                # Parse dependency line
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1]
                    deps.append(Dependency(
                        ecosystem="Go",
                        name=name,
                        version=version,
                        manifest=path
                    ))
    return deps


def parse_pom_xml(path: str) -> list[Dependency]:
    """Parse pom.xml for Maven dependencies (best-effort)."""
    deps = []
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except (OSError, IOError, ET.ParseError):
        return deps

    # Handle namespaces (pom.xml typically uses Maven namespace)
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}

    # Try to find dependencies with namespace first
    dependencies = root.findall(".//m:dependency", ns)

    # If no results, try without namespace
    if not dependencies:
        dependencies = root.findall(".//dependency")

    for dep in dependencies:
        # Try to get elements with namespace first, then without
        group_elem = dep.find("m:groupId", ns) or dep.find("groupId")
        artifact_elem = dep.find("m:artifactId", ns) or dep.find("artifactId")
        version_elem = dep.find("m:version", ns) or dep.find("version")

        # Handle elements with embedded namespace in tag
        if group_elem is None:
            group_elem = dep.find("{http://maven.apache.org/POM/4.0.0}groupId")
        if artifact_elem is None:
            artifact_elem = dep.find("{http://maven.apache.org/POM/4.0.0}artifactId")
        if version_elem is None:
            version_elem = dep.find("{http://maven.apache.org/POM/4.0.0}version")

        group_id = group_elem.text if group_elem is not None else ""
        artifact_id = artifact_elem.text if artifact_elem is not None else ""
        version = version_elem.text if version_elem is not None else ""

        if group_id and artifact_id and version:
            # Maven convention: name is group:artifact
            name = f"{group_id}:{artifact_id}"
            deps.append(Dependency(
                ecosystem="Maven",
                name=name,
                version=version,
                manifest=path
            ))

    return deps


def parse_gemfile_lock(path: str) -> list[Dependency]:
    """Parse Gemfile.lock for Ruby dependencies (basic parsing)."""
    deps = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            content = fh.read()
    except (OSError, IOError):
        return deps

    # Gemfile.lock format: GEM section lists gems with versions
    # Example:
    #   GEM
    #     remote: ...
    #     specs:
    #       gem_name (version)
    in_gem_section = False
    for line in content.split("\n"):
        if line.startswith("GEM"):
            in_gem_section = True
            continue
        if in_gem_section and line and not line.startswith(" "):
            in_gem_section = False
        if in_gem_section:
            # Look for lines like "  gem_name (version)"
            match = re.match(r"^\s+([a-z0-9_-]+)\s+\(([^)]+)\)$", line)
            if match:
                name, version = match.groups()
                # Clean up version (might have multiple parts)
                version = version.split(",")[0].strip()
                deps.append(Dependency(
                    ecosystem="RubyGems",
                    name=name,
                    version=version,
                    manifest=path
                ))
    return deps


def parse_manifest(path: str) -> list[Dependency]:
    """Dispatch to the appropriate parser based on filename."""
    filename = os.path.basename(path)

    if filename.startswith("requirements") and filename.endswith(".txt"):
        return parse_requirements_txt(path)
    elif filename == "Pipfile.lock":
        return parse_requirements_txt(path)  # Pragmatic fallback
    elif filename == "poetry.lock":
        # poetry.lock is TOML; for now return empty (optional simple parser)
        return []
    elif filename == "package.json":
        return parse_package_json(path)
    elif filename == "package-lock.json":
        return parse_package_lock(path)
    elif filename == "go.mod":
        return parse_go_mod(path)
    elif filename == "pom.xml":
        return parse_pom_xml(path)
    elif filename == "Gemfile.lock":
        return parse_gemfile_lock(path)
    return []


def collect_dependencies(root: str) -> list[Dependency]:
    """Find all manifests in root, parse them, and return a deduped list of dependencies."""
    root = os.path.abspath(root)
    manifests = find_manifests(root)

    all_deps: list[Dependency] = []
    for manifest_path in manifests:
        all_deps.extend(parse_manifest(manifest_path))

    # Dedupe: keep only unique (ecosystem, name, version, manifest) tuples
    seen = set()
    deduped = []
    for dep in all_deps:
        key = (dep.ecosystem, dep.name, dep.version, dep.manifest)
        if key not in seen:
            seen.add(key)
            deduped.append(dep)

    return deduped

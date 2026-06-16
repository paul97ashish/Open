"""Tests for dependency manifest parsing."""

import os
import tempfile
from pathlib import Path

import pytest

from vulnhound.deps.manifests import (
    Dependency,
    collect_dependencies,
    find_manifests,
    parse_gemfile_lock,
    parse_go_mod,
    parse_manifest,
    parse_package_json,
    parse_package_lock,
    parse_pom_xml,
    parse_requirements_txt,
)


class TestParseRequirementsTxt:
    """Test requirements.txt parsing."""

    def test_simple_pinned_deps(self, tmp_path):
        """Parse simple name==version entries."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.19.1\npyyaml==5.1\n")

        deps = parse_requirements_txt(str(req_file))
        assert len(deps) == 2
        assert deps[0].ecosystem == "PyPI"
        assert deps[0].name == "requests"
        assert deps[0].version == "2.19.1"
        assert deps[1].name == "pyyaml"
        assert deps[1].version == "5.1"
        assert all(d.manifest == str(req_file) for d in deps)

    def test_ignore_comments_and_blanks(self, tmp_path):
        """Skip comment and blank lines."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("# comment\nrequests==2.19.1\n\n# another\npyyaml==5.1\n")

        deps = parse_requirements_txt(str(req_file))
        assert len(deps) == 2

    def test_ignore_markers_and_extras(self, tmp_path):
        """Handle lines with markers and extras (pragmatic)."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.19.1; python_version >= '3.6'\npyyaml==5.1[extra]\n")

        deps = parse_requirements_txt(str(req_file))
        assert len(deps) == 2
        assert deps[0].name == "requests"
        assert deps[1].name == "pyyaml"

    def test_ignore_dashes_and_unpinned(self, tmp_path):
        """Skip -r includes and unpinned versions."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("-r other.txt\nrequests\nrequests>=2.0\nrequests==2.19.1\n")

        deps = parse_requirements_txt(str(req_file))
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "2.19.1"

    def test_nonexistent_file(self):
        """Gracefully handle missing files."""
        deps = parse_requirements_txt("/nonexistent/requirements.txt")
        assert deps == []


class TestParsePackageJson:
    """Test package.json parsing."""

    def test_dependencies_and_dev_dependencies(self, tmp_path):
        """Parse dependencies and devDependencies."""
        pkg_file = tmp_path / "package.json"
        pkg_file.write_text("""{
            "dependencies": {"lodash": "4.17.15", "express": "^4.16.0"},
            "devDependencies": {"jest": "~25.0.0"}
        }""")

        deps = parse_package_json(str(pkg_file))
        assert len(deps) == 3
        names = {d.name for d in deps}
        assert names == {"lodash", "express", "jest"}
        # Check that ^ and ~ are stripped
        express = next(d for d in deps if d.name == "express")
        assert express.version == "4.16.0"
        jest = next(d for d in deps if d.name == "jest")
        assert jest.version == "25.0.0"

    def test_ecosystem_is_npm(self, tmp_path):
        """Verify ecosystem is npm."""
        pkg_file = tmp_path / "package.json"
        pkg_file.write_text('{"dependencies": {"lodash": "4.17.15"}}')

        deps = parse_package_json(str(pkg_file))
        assert all(d.ecosystem == "npm" for d in deps)

    def test_empty_json(self, tmp_path):
        """Handle empty package.json."""
        pkg_file = tmp_path / "package.json"
        pkg_file.write_text("{}")

        deps = parse_package_json(str(pkg_file))
        assert deps == []

    def test_invalid_json(self, tmp_path):
        """Gracefully handle invalid JSON."""
        pkg_file = tmp_path / "package.json"
        pkg_file.write_text("{invalid json}")

        deps = parse_package_json(str(pkg_file))
        assert deps == []


class TestParsePackageLock:
    """Test package-lock.json parsing."""

    def test_packages_format(self, tmp_path):
        """Parse modern package-lock.json with packages object."""
        lock_file = tmp_path / "package-lock.json"
        lock_file.write_text("""{
            "packages": {
                "": {"name": "myapp"},
                "node_modules/lodash": {"version": "4.17.15"},
                "node_modules/express": {"version": "4.16.0"}
            }
        }""")

        deps = parse_package_lock(str(lock_file))
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert names == {"lodash", "express"}

    def test_dependencies_fallback(self, tmp_path):
        """Fall back to dependencies object for older format."""
        lock_file = tmp_path / "package-lock.json"
        lock_file.write_text("""{
            "dependencies": {
                "lodash": {"version": "4.17.15"},
                "express": {"version": "4.16.0"}
            }
        }""")

        deps = parse_package_lock(str(lock_file))
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert names == {"lodash", "express"}


class TestParseGoMod:
    """Test go.mod parsing."""

    def test_require_block(self, tmp_path):
        """Parse require blocks."""
        go_file = tmp_path / "go.mod"
        go_file.write_text("""module example.com/myapp

require (
    github.com/some/module v1.2.3
    github.com/other/lib v0.1.0
)
""")

        deps = parse_go_mod(str(go_file))
        assert len(deps) == 2
        assert deps[0].ecosystem == "Go"
        assert deps[0].name == "github.com/some/module"
        assert deps[0].version == "v1.2.3"

    def test_single_require_lines(self, tmp_path):
        """Parse individual require statements."""
        go_file = tmp_path / "go.mod"
        go_file.write_text("""module example.com/myapp
require github.com/some/module v1.2.3
require github.com/other/lib v0.1.0
""")

        deps = parse_go_mod(str(go_file))
        assert len(deps) == 2
        assert deps[0].name == "github.com/some/module"

    def test_mixed_require_formats(self, tmp_path):
        """Handle both block and line formats."""
        go_file = tmp_path / "go.mod"
        go_file.write_text("""module example.com/myapp
require github.com/direct/lib v0.5.0
require (
    github.com/some/module v1.2.3
    github.com/other/lib v0.1.0
)
""")

        deps = parse_go_mod(str(go_file))
        assert len(deps) == 3


class TestParsePomXml:
    """Test pom.xml parsing."""

    def test_basic_dependencies(self, tmp_path):
        """Parse Maven dependencies."""
        pom_file = tmp_path / "pom.xml"
        pom_file.write_text("""<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>org.apache.log4j</groupId>
            <artifactId>log4j</artifactId>
            <version>2.11.0</version>
        </dependency>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.12</version>
        </dependency>
    </dependencies>
</project>
""")

        deps = parse_pom_xml(str(pom_file))
        assert len(deps) == 2
        assert deps[0].ecosystem == "Maven"
        assert "log4j" in deps[0].name
        assert deps[0].version == "2.11.0"

    def test_maven_name_format(self, tmp_path):
        """Verify Maven name is group:artifact."""
        pom_file = tmp_path / "pom.xml"
        pom_file.write_text("""<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>com.google</groupId>
            <artifactId>gson</artifactId>
            <version>2.8.0</version>
        </dependency>
    </dependencies>
</project>
""")

        deps = parse_pom_xml(str(pom_file))
        assert len(deps) == 1
        assert deps[0].name == "com.google:gson"


class TestParseGemfileLock:
    """Test Gemfile.lock parsing."""

    def test_basic_gems(self, tmp_path):
        """Parse Gem entries."""
        gem_file = tmp_path / "Gemfile.lock"
        gem_file.write_text("""GEM
  remote: https://rubygems.org/
  specs:
    bundler (2.0.1)
    rake (10.5.0)

BUNDLED WITH
   2.0.1
""")

        deps = parse_gemfile_lock(str(gem_file))
        assert len(deps) == 2
        assert all(d.ecosystem == "RubyGems" for d in deps)
        names = {d.name for d in deps}
        assert names == {"bundler", "rake"}


class TestFindManifests:
    """Test manifest file discovery."""

    def test_find_requirements_txt(self, tmp_path):
        """Find requirements.txt files."""
        (tmp_path / "requirements.txt").touch()
        (tmp_path / "requirements-dev.txt").touch()
        manifests = find_manifests(str(tmp_path))
        assert len(manifests) == 2
        basenames = {os.path.basename(m) for m in manifests}
        assert basenames == {"requirements.txt", "requirements-dev.txt"}

    def test_find_nested_manifests(self, tmp_path):
        """Find manifests in subdirectories."""
        (tmp_path / "requirements.txt").touch()
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "package.json").touch()
        manifests = find_manifests(str(tmp_path))
        assert len(manifests) == 2

    def test_skip_ignored_dirs(self, tmp_path):
        """Skip .git, node_modules, venv, etc."""
        (tmp_path / "requirements.txt").touch()
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "package.json").touch()
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "package.json").touch()

        manifests = find_manifests(str(tmp_path))
        assert len(manifests) == 1
        assert "requirements.txt" in manifests[0]

    def test_find_multiple_types(self, tmp_path):
        """Find multiple manifest types."""
        (tmp_path / "requirements.txt").touch()
        (tmp_path / "package.json").touch()
        (tmp_path / "go.mod").touch()

        manifests = find_manifests(str(tmp_path))
        assert len(manifests) == 3


class TestParseManifest:
    """Test the dispatch function."""

    def test_dispatch_to_requirements(self, tmp_path):
        """Dispatch to requirements.txt parser."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.19.1\n")

        deps = parse_manifest(str(req_file))
        assert len(deps) == 1
        assert deps[0].ecosystem == "PyPI"

    def test_dispatch_to_package_json(self, tmp_path):
        """Dispatch to package.json parser."""
        pkg_file = tmp_path / "package.json"
        pkg_file.write_text('{"dependencies": {"lodash": "4.17.15"}}')

        deps = parse_manifest(str(pkg_file))
        assert len(deps) == 1
        assert deps[0].ecosystem == "npm"

    def test_dispatch_to_go_mod(self, tmp_path):
        """Dispatch to go.mod parser."""
        go_file = tmp_path / "go.mod"
        go_file.write_text("module example.com\nrequire github.com/some/lib v1.0.0\n")

        deps = parse_manifest(str(go_file))
        assert len(deps) == 1
        assert deps[0].ecosystem == "Go"


class TestCollectDependencies:
    """Test the full collection pipeline."""

    def test_collect_from_multiple_manifests(self, tmp_path):
        """Collect deps from multiple manifest files."""
        (tmp_path / "requirements.txt").write_text("requests==2.19.1\n")
        (tmp_path / "package.json").write_text('{"dependencies": {"lodash": "4.17.15"}}')

        deps = collect_dependencies(str(tmp_path))
        assert len(deps) == 2
        ecosystems = {d.ecosystem for d in deps}
        assert ecosystems == {"PyPI", "npm"}

    def test_dedupe_identical_deps(self, tmp_path):
        """Dedupe identical dependencies."""
        # Create two requirement files with the same dependency
        (tmp_path / "requirements.txt").write_text("requests==2.19.1\n")
        (tmp_path / "requirements-dev.txt").write_text("requests==2.19.1\n")

        deps = collect_dependencies(str(tmp_path))
        # Should be deduped by (ecosystem, name, version, manifest)
        # since the manifest is different, we expect 2
        assert len(deps) == 2

    def test_empty_directory(self, tmp_path):
        """Handle empty directory."""
        deps = collect_dependencies(str(tmp_path))
        assert deps == []

    def test_directory_with_no_manifests(self, tmp_path):
        """Handle directory with no manifests."""
        (tmp_path / "README.md").write_text("# readme")
        deps = collect_dependencies(str(tmp_path))
        assert deps == []

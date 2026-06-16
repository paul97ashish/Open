import json

from vulnhound.findings import Finding, Severity
from vulnhound.reporters import get_reporter, sarif
from vulnhound.reporters.terminal import severity_exit_code


def mk(**kw):
    base = dict(title="SQL Injection", severity=Severity.HIGH, source="sast",
                description="user input concatenated into query")
    base.update(kw)
    return Finding(**base)


def test_get_reporter_dispatch():
    assert get_reporter("sarif") is sarif
    assert get_reporter("SARIF") is sarif
    try:
        get_reporter("nope")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_sarif_is_valid_shape():
    findings = [mk(cwe="CWE-89", file="app.py", start_line=10, end_line=12)]
    out = sarif.render(findings, target="app/")
    doc = json.loads(out)
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "vulnhound"
    assert run["tool"]["driver"]["rules"], "rules should be populated"
    result = run["results"][0]
    assert result["ruleId"] == "CWE-89"
    assert result["level"] == "error"  # HIGH -> error
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "app.py"
    assert loc["region"]["startLine"] == 10
    assert loc["region"]["endLine"] == 12


def test_sarif_level_mapping():
    out = sarif.render([mk(severity=Severity.INFO, cwe="CWE-1")])
    doc = json.loads(out)
    assert doc["runs"][0]["results"][0]["level"] == "none"


def test_sarif_omits_region_without_lines():
    out = sarif.render([mk(file="x.py", start_line=0, end_line=0, cwe="CWE-1")])
    doc = json.loads(out)
    phys = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert "region" not in phys


def test_sarif_no_location_without_file():
    out = sarif.render([mk(file="", cwe="CWE-1")])
    doc = json.loads(out)
    assert "locations" not in doc["runs"][0]["results"][0]


def test_empty_findings_valid():
    doc = json.loads(sarif.render([]))
    assert doc["runs"][0]["results"] == []


def test_severity_exit_code():
    findings = [mk(severity=Severity.MEDIUM)]
    assert severity_exit_code(findings, Severity.HIGH) == 0
    assert severity_exit_code(findings, Severity.LOW) == 1
    assert severity_exit_code([], Severity.INFO) == 0

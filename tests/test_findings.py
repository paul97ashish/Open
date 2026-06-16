from vulnhound.findings import (
    Finding,
    Severity,
    dedupe,
    max_severity,
    severity_counts,
    sort_findings,
)


def mk(**kw):
    base = dict(title="x", severity=Severity.LOW, source="sast", description="d")
    base.update(kw)
    return Finding(**base)


def test_severity_from_str_tolerant():
    assert Severity.from_str("critical") is Severity.CRITICAL
    assert Severity.from_str("CRITICAL") is Severity.CRITICAL
    assert Severity.from_str("moderate") is Severity.MEDIUM
    assert Severity.from_str("nonsense") is Severity.INFO
    assert Severity.from_str(None) is Severity.INFO
    assert Severity.from_str(3) is Severity.HIGH
    assert Severity.from_str(99) is Severity.INFO


def test_severity_ordering_and_label():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM
    assert Severity.HIGH.label == "high"


def test_finding_roundtrip():
    f = mk(severity=Severity.HIGH, cwe="89", file="a.py", start_line=10, end_line=12,
           confidence=0.9, references=["r1"])
    d = f.to_dict()
    assert d["severity"] == "high"
    assert d["cwe"] == "CWE-89"
    f2 = Finding.from_dict(d)
    assert f2.severity is Severity.HIGH
    assert f2.cwe == "CWE-89"
    assert f2.start_line == 10 and f2.end_line == 12
    assert f2.references == ["r1"]


def test_from_dict_is_tolerant_of_missing_keys():
    f = Finding.from_dict({"title": "only title"})
    assert f.title == "only title"
    assert f.severity is Severity.INFO
    assert f.source == "sast"


def test_post_init_swaps_inverted_lines():
    f = mk(start_line=20, end_line=5)
    assert f.start_line == 5 and f.end_line == 20


def test_dedupe_merges_overlapping_same_cwe():
    a = mk(severity=Severity.LOW, cwe="CWE-89", file="a.py", start_line=10, end_line=12,
           references=["r1"])
    b = mk(severity=Severity.HIGH, cwe="CWE-89", file="a.py", start_line=11, end_line=15,
           references=["r2"])
    out = dedupe([a, b])
    assert len(out) == 1
    assert out[0].severity is Severity.HIGH  # higher kept
    assert set(out[0].references) == {"r1", "r2"}


def test_dedupe_keeps_distinct_cwe():
    a = mk(cwe="CWE-89", file="a.py", start_line=10, end_line=12)
    b = mk(cwe="CWE-79", file="a.py", start_line=10, end_line=12)
    assert len(dedupe([a, b])) == 2


def test_dedupe_distinct_files():
    a = mk(cwe="CWE-89", file="a.py", start_line=1, end_line=1)
    b = mk(cwe="CWE-89", file="b.py", start_line=1, end_line=1)
    assert len(dedupe([a, b])) == 2


def test_sort_and_max_severity():
    findings = [mk(severity=Severity.LOW), mk(severity=Severity.CRITICAL),
                mk(severity=Severity.MEDIUM)]
    ordered = sort_findings(findings)
    assert ordered[0].severity is Severity.CRITICAL
    assert max_severity(findings) is Severity.CRITICAL


def test_severity_counts():
    findings = [mk(severity=Severity.LOW), mk(severity=Severity.LOW),
                mk(severity=Severity.HIGH)]
    counts = severity_counts(findings)
    assert counts["low"] == 2 and counts["high"] == 1 and counts["info"] == 0

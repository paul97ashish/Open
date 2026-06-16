# vulnhound — Frozen Interface Contract

This is the **contract** every scan-mode module builds against. The shared core
(`findings`, `model_client`, `prompts`, `reporters`, `config`) is implemented and
its tests pass. **Do not edit files you do not own.** Each agent owns a disjoint
set of files (see `PROGRESS.md`).

Package layout: `src/vulnhound/...` (src layout, importable as `vulnhound`).

---

## 1. Findings model — `vulnhound.findings`

```python
class Severity(enum.IntEnum):
    INFO = 0; LOW = 1; MEDIUM = 2; HIGH = 3; CRITICAL = 4
    @classmethod
    def from_str(cls, value) -> "Severity"   # tolerant; unknown/None -> INFO
    @property
    def label(self) -> str                   # e.g. "high"

SOURCES = ("sast", "deps", "dast")

@dataclass
class Finding:
    title: str
    severity: Severity            # accepts a str too; normalised in __post_init__
    source: str                   # "sast" | "deps" | "dast"
    description: str
    recommendation: str = ""
    cwe: str = ""                 # auto-normalised to "CWE-<n>"
    file: str = ""                # sast/deps: path; dast: URL
    start_line: int = 0
    end_line: int = 0
    confidence: float = 0.5       # 0..1
    references: list[str] = []
    extra: dict = {}
    def to_dict(self) -> dict
    @classmethod
    def from_dict(cls, d: dict) -> "Finding"   # tolerant of missing keys
    def key(self) -> tuple

def dedupe(findings) -> list[Finding]          # merge near-dupes, sorted sev DESC
def sort_findings(findings) -> list[Finding]
def max_severity(findings) -> Severity
def severity_counts(findings) -> dict[str,int] # {"info":0,"low":..,...}
```

**How to build a Finding per source:**
- **sast:** `Finding(title, severity, "sast", description, recommendation, cwe,
  file=relpath, start_line, end_line, confidence)`
- **deps:** `Finding(title, severity, "deps", description, recommendation, cwe,
  file=manifest_path, extra={"package":..,"version":..,"ecosystem":..,"fixed_version":..},
  references=[advisory_urls])`
- **dast:** `Finding(title, severity, "dast", description, recommendation, cwe,
  file=url, start_line=0, end_line=0, confidence)`

The CLI/web layer turns model JSON into Findings via `Finding.from_dict(d)` after
`prompts.parse_findings_json(...)`. Set `source`/`file` yourself afterwards if the
model didn't supply them.

---

## 2. Model client — `vulnhound.model_client`

```python
class ModelClient:
    def __init__(self, model, base_url=None, api_key=None,
                 temperature=0.1, timeout=120.0, max_retries=2)
    def complete(self, system: str, user: str) -> str   # returns assistant text

class MockClient(ModelClient):
    # OFFLINE. Never imports openai, never hits network.
    def __init__(self, responses: dict[str,str] | None = None, default: str = "[]")
    # complete(system,user): returns the value of the first `responses` key that is
    # a SUBSTRING of `user`; else `default`. Records calls in self.calls.

def get_client(config) -> ModelClient
    # returns MockClient when config.mock is truthy (using config.mock_responses /
    # config.mock_default), else a real ModelClient from config fields.
```

**Testing tip:** seed `Config(mock=True, mock_responses={"app.py": "[{...}]"})` so a
prompt containing `app.py` returns that canned JSON. Default `"[]"` => no findings.

---

## 3. Prompts — `vulnhound.prompts`

```python
SECURITY_AUDITOR_SYSTEM: str            # system prompt; demands a strict JSON array
build_sast_user(path, numbered_code) -> str
build_deps_triage_user(package, version, osv_summaries) -> str
build_dast_user(url, evidence) -> str
parse_findings_json(raw: str) -> list[dict]   # robust; never raises; [] on failure
```

`parse_findings_json` strips code fences/prose, accepts an array or a single object,
and returns a list of plain dicts. Feed each dict to `Finding.from_dict`.

---

## 4. Reporters — `vulnhound.reporters`

```python
get_reporter(fmt) -> module           # fmt in {"terminal","json","sarif"}; else ValueError
# every reporter module exposes:
render(findings, target="") -> str
# terminal reporter ALSO:
from vulnhound.reporters.terminal import severity_exit_code
severity_exit_code(findings, threshold: Severity) -> int   # 1 if any >= threshold else 0
```

`json` -> JSON string with summary + findings. `sarif` -> SARIF 2.1.0 string.
`terminal` -> prints a rich table and returns a plain-text version.

---

## 5. Config — `vulnhound.config`

```python
@dataclass
class Config:
    model="" ; base_url=None ; api_key=None ; mock=False ; temperature=0.1
    severity_threshold=Severity.LOW ; concurrency=4 ; fmt="terminal" ; output=None
    authorized=False                 # REQUIRED gate before any DAST run
    extra: dict = {}                 # scan-mode knobs (max_files, globs, max_depth, ...)
    mock_responses: dict|None = None ; mock_default="[]"
    @classmethod
    def from_args(cls, args) -> "Config"   # args = argparse.Namespace OR dict
load_yaml(path) -> dict
```

Env fallbacks: `VULNHOUND_MODEL`, `VULNHOUND_BASE_URL`, `VULNHOUND_API_KEY`.

---

## 6. Scanner module contract (THE important one for Wave 1)

Each scan mode exposes a single entry point:

```python
# vulnhound/sast/scanner.py , vulnhound/deps/scanner.py , vulnhound/dast/scanner.py
def run(config: Config, target: str) -> list[Finding]: ...
```

- `target` is a filesystem path (sast/deps) or a URL (dast).
- Build the model client with `vulnhound.model_client.get_client(config)`.
- Use the relevant `prompts.build_*` + `prompts.parse_findings_json`, wrap dicts in
  `Finding.from_dict`, set `source`/`file`, then return `dedupe(findings)`.
- **DAST `run` MUST raise `PermissionError` (or return after a clear error) if
  `config.authorized` is not True.** Keep request volume low and same-origin.
- Reporting and exit codes are handled by the CLI/web layer — scanners only return
  `list[Finding]`.

The web UI (`vulnhound/web/app.py`) and CLI (`vulnhound/cli.py`) import these
`run` functions and the reporters. The CLI maps subcommands:
`scan code` -> sast, `scan deps` -> deps, `scan web` -> dast, `serve` -> web app.

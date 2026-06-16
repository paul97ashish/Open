# vulnhound

**An LLM-powered cybersecurity vulnerability harness that works with _any_
open-source model.**

vulnhound points a local or self-hosted language model at your code and systems to
find security vulnerabilities. It talks to any **OpenAI-compatible API** — so it
works out of the box with [Ollama](https://ollama.com), vLLM, LM Studio, and the
llama.cpp server — and it never sends your code to a third-party cloud unless you
explicitly point it at one.

> ⚠️ **Authorized use only.** vulnhound is a *defensive* security tool. Run the
> code and dependency scanners on software you own or are authorized to review.
> The dynamic web scanner (DAST) **refuses to run without an explicit
> `--authorized` flag** — only test systems you own or have written permission to
> assess.

---

## Scan modes

| Mode | Command | What it does |
|---|---|---|
| **SAST** | `vulnhound scan code <path>` | LLM reads your source (or a git diff) and flags vulnerabilities with line numbers and CWE ids. |
| **Dependencies** | `vulnhound scan deps <path>` | Parses manifests/lockfiles and checks them against the free [OSV.dev](https://osv.dev) vulnerability database; the model triages severity and upgrade advice. |
| **DAST** | `vulnhound scan web <url> --authorized` | Bounded, same-origin crawl + lightweight checks (security headers, cookie flags, reflected input, open redirect, verbose errors), with model-assisted analysis. |
| **Web UI** | `vulnhound serve` | A local dashboard to launch any scan and browse/export findings. |

All modes share one findings model and three reporters: **terminal**, **JSON**, and
**SARIF 2.1.0** (uploadable to GitHub code scanning).

---

## Install

```bash
pip install -e .            # from the repo root
# for the test suite:
pip install -e ".[dev]"
```

Requires Python ≥ 3.9.

## Connect a model

vulnhound needs an OpenAI-compatible endpoint. With Ollama, for example:

```bash
ollama pull qwen2.5-coder
vulnhound scan code ./myapp \
  --base-url http://localhost:11434/v1 \
  --model qwen2.5-coder
```

You can also configure via environment variables:

```bash
export VULNHOUND_BASE_URL=http://localhost:11434/v1
export VULNHOUND_MODEL=qwen2.5-coder
# export VULNHOUND_API_KEY=...   # only if your endpoint needs one
vulnhound scan code ./myapp
```

### No model handy? Try offline mock mode

Every scan mode runs fully offline with a built-in mock model — useful for trying
the workflow, demos, and CI smoke tests:

```bash
vulnhound scan code examples/ --mock
vulnhound scan deps examples/ --mock
```

---

## Usage examples

```bash
# Static analysis, fail CI if anything >= high severity, write SARIF
vulnhound scan code ./src --model qwen2.5-coder \
  --base-url http://localhost:11434/v1 \
  --severity-threshold high --format sarif --output results.sarif

# Only scan what changed on this branch
vulnhound scan code . --diff origin/main --model qwen2.5-coder \
  --base-url http://localhost:11434/v1

# Dependency CVE scan, JSON output
vulnhound scan deps ./myproject --format json --output deps.json

# Authorized dynamic scan of a staging app you control
vulnhound scan web https://staging.internal.example --authorized \
  --model qwen2.5-coder --base-url http://localhost:11434/v1

# Web dashboard
vulnhound serve            # then open http://127.0.0.1:8000
```

### Exit codes

`vulnhound scan ...` exits **non-zero** when any finding is at or above
`--severity-threshold` (default `low`), so it drops straight into CI gates.

---

## Common options (scan)

| Flag | Meaning |
|---|---|
| `--model` | model name (env `VULNHOUND_MODEL`) |
| `--base-url` | OpenAI-compatible base URL (env `VULNHOUND_BASE_URL`) |
| `--api-key-env` | name of an env var holding the API key |
| `--format {terminal,json,sarif}` | report format |
| `--output FILE` | write the report to a file |
| `--severity-threshold {info,low,medium,high,critical}` | CI fail threshold |
| `--mock` | offline mode (built-in mock model, no network) |
| `--concurrency N` | parallel workers (SAST) |
| `--diff [REF]` | SAST: only changed files vs REF (default `HEAD`) |
| `--authorized` | DAST: confirm you may test the target (required) |

---

## How it works

```
 target ──► collector ──►  prompt  ──►  open-source model  ──►  JSON findings
 (code/                 (per mode)     (OpenAI-compatible)        │
  deps/                                                           ▼
  url)                                              Finding model + dedupe
                                                                  │
                                          terminal / JSON / SARIF reports
```

The model client (`vulnhound.model_client`) is provider-agnostic; the same
`Finding` data model and reporters serve every scan mode. See `INTERFACES.md` for
the internal contract and `PROGRESS.md` for the build breakdown.

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

## Disclaimer

vulnhound assists human reviewers — it does not replace them. LLM findings can
include false positives and miss real issues; always validate results. Use only
against assets you are authorized to test.

## License

MIT

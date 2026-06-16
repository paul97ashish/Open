# vulnhound — Build Progress Board

Single source of truth for the parallel multi-agent build. **Each agent flips only
its own rows** to `doing`/`done` and records blockers in Notes. Agents own disjoint
files — never edit another agent's files. The frozen contract is in `INTERFACES.md`.

Status legend: `todo` · `doing` · `done` · `blocked`

## Wave 0 — Foundation (shared core)  [model: orchestrator/sonnet]
| Task | Owner | Status | Notes |
|---|---|---|---|
| pyproject.toml + .gitignore | Foundation | done | src layout, console script `vulnhound` |
| findings.py (Severity, Finding, dedupe) | Foundation | done | 17 tests pass |
| model_client.py (ModelClient + MockClient + get_client) | Foundation | done | offline MockClient |
| prompts.py (system + builders + parse_findings_json) | Foundation | done | robust JSON parse |
| config.py (Config + from_args + load_yaml) | Foundation | done | env fallbacks |
| reporters/ (terminal, json, sarif) | Foundation | done | SARIF 2.1.0 |
| tests/test_findings.py, tests/test_sarif.py | Foundation | done | green |
| INTERFACES.md (frozen contract) | Foundation | done | — |

## Wave 1 — Feature modules (parallel)
| Task | Owner | Status | Notes |
|---|---|---|---|
| sast/ collector.py + scanner.py | SAST | done | 35 tests pass; collector (discover_files, number_lines, chunk_file, changed_files) + scanner.run() with concurrency, dedupe, offline MockClient |
| deps/ manifests.py + osv.py + scanner.py | Deps | done | 41 tests pass; 8 manifest parsers (requirements.txt, package.json, go.mod, pom.xml, Gemfile.lock, etc.), OSV querybatch, offline mock mode |
| dast/ crawler.py + checks.py + scanner.py | DAST | done | 43 tests pass; bounded same-origin crawl, 6 passive checks, authorization gate, offline MockClient/LLM |
| web/ app.py + templates + static | Web | done | 20 tests pass; FastAPI with Jinja2 templates, lazy scanner loading, mock testing |

## Wave 2 — Integration
| Task | Owner | Status | Notes |
|---|---|---|---|
| cli.py (scan code/deps/web, serve) | Integration | done | argparse: scan code/deps/web + serve; CI exit codes; lazy scanner import |
| README.md (usage + authorized-use notice) | Integration | done | install, model setup, all modes, authorized-use notice |
| full `pytest` + smoke tests + commit/push | Integration | done | 156 tests pass; CLI smoke (sast/deps/dast gate/sarif/json) + web app verified |

## How to update
1. Read `INTERFACES.md` first; build only against those signatures.
2. Flip your row to `doing` when you start, `done` when your tests pass.
3. If you need an interface change, set your row `blocked` with a Note describing
   exactly what you need; do not edit shared-core files yourself.

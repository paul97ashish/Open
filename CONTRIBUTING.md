# Contributing to vulnhound

Thanks for your interest! vulnhound is a defensive security tool — contributions
that improve detection quality, add scanners/reporters, or broaden model support
are very welcome.

## Development setup

```bash
pip install -e ".[dev]"
pytest -q
```

All tests must run **offline** — use the `MockClient` (via `Config(mock=True)`)
and canned fixtures rather than real models or network calls.

## Architecture

- `INTERFACES.md` is the internal contract: the `Finding` model, the
  `ModelClient`/`MockClient`, prompt builders, reporters, and the scanner
  contract `run(config, target) -> list[Finding]`.
- Each scan mode lives in its own package: `sast/`, `deps/`, `dast/`, `web/`.
- To add a new scan mode: create a package exposing `run(config, target)`, add a
  subcommand in `cli.py`, and add offline tests.

## Guidelines

- Favor precision over recall — avoid noisy, low-signal findings.
- Keep new dependencies minimal.
- Add tests for new behavior; keep the suite green and offline.
- Never add code that targets systems without authorization, evades detection, or
  is purpose-built for offensive misuse.

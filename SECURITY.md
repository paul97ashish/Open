# Security Policy

## Responsible use

vulnhound is a **defensive** security tool. Only run it against systems and code
you own or are explicitly authorized to assess:

- `scan code` and `scan deps` analyze local files — use them on your own repos.
- `scan web` (DAST) sends requests to a live target and **requires `--authorized`**.
  Testing systems without permission may be illegal. You are responsible for
  ensuring you have authorization.

## Reporting a vulnerability in vulnhound

If you discover a security issue in vulnhound itself, please report it privately
via GitHub Security Advisories ("Report a vulnerability" on the Security tab)
rather than opening a public issue. We aim to acknowledge reports within a few
business days.

## Scope notes

- vulnhound talks only to the model endpoint you configure (`--base-url`). With a
  local endpoint (e.g. Ollama) your source never leaves your machine.
- LLM findings are advisory: they can include false positives and miss real
  issues. Always have a human validate results before acting on them.

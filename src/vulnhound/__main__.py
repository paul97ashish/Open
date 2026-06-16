"""Entry point for ``python -m vulnhound``.

Imports the CLI lazily so this module stays importable even before optional
pieces are installed.
"""


def _run() -> int:
    from vulnhound.cli import main

    return main()


if __name__ == "__main__":
    raise SystemExit(_run())

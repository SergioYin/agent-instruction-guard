# AGENTS.md

Guidance for AI coding agents working on this repository.

- Keep the package zero-dependency and standard-library-only.
- After changes, run `python -m unittest discover -s tests -v` and `python scripts/selfcheck.py`.
- Do not add `.github/workflows/*` unless GitHub token workflow scope is confirmed.
- Do not commit caches, virtualenvs, build outputs, `.env`, private keys, or real credentials.
- Scanner excerpts must redact likely secrets before printing.

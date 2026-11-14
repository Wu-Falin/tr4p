# Contributing

Thanks for looking. A few rules keep this project trustworthy.

## Hard limits

Changes that cross these are not accepted, whatever the reason:

- Everything stays on the defender's server and in its own responses.
  Nothing may run on, crash, alter or open anything on a visitor's machine.
  No exploits against clients, no decompression bombs, no popups or script
  loops, no shock imagery.
- Nothing an attacker sends is executed, evaluated, used as a file name, or
  passed to a database or shell. Fake features are emulations that print
  text.
- Decoy data is synthetic. Never add real customer data, real brands, real
  people or real contact details. Use the reserved example domains,
  documentation address ranges and fictional phone ranges.
- No secret-looking strings in the repository, including tests and docs.
  Fake secrets are made at run time. Build test fixtures dynamically.
- No obfuscated code. The source is meant to be read.

## Getting started

```bash
pip install -e ".[dev]"
python -m pytest
python scripts/audit-footprints
```

## What a good change looks like

- Small and focused, with tests. New detection signals need tests for both
  the attacker case and the ordinary-visitor case.
- A single signal must never do more than log. If you add a signal, give it
  an evidence group in `scoring.py` and say why it is independent of the
  existing ones.
- Anything added to the protected site's own pages must fail open: if it
  breaks, the visitor gets the original page.
- Anything on the decoy path must fail closed: a high-tier session never
  reaches the real site.
- Responses must not identify the project. Tests check this.
- Keep resource use bounded. Every queue, cache and buffer has a cap.
- Plain words in docs and comments. Honest about limits; never "undetectable"
  or "foolproof".

## Before you open a pull request

1. `python -m pytest` passes.
2. `python scripts/audit-footprints` is clean: no machine names, home paths,
   addresses outside the documentation ranges, or stray e-mail addresses.
3. Docs are updated if behaviour changed, including the Limitations section
   of the README when a limit is added or removed.

## Reporting security problems

Not in a public issue. See [SECURITY.md](SECURITY.md).

"""TR4P: a self-hosted deception layer for sites you own or are authorized to protect."""

import sys

# Written for old interpreters on purpose: this must run (and explain itself)
# even where the rest of the package cannot be imported.
if sys.version_info < (3, 10):   # pragma: no cover - exercised by a CI step on an old Python
    sys.stderr.write(
        "TR4P needs Python 3.10 or newer; this is Python %d.%d.\n"
        "Install a newer Python (python.org, your package manager, or Homebrew) and run:\n"
        "  python3 -m pip install tr4p   (or: pipx install tr4p)\n" % sys.version_info[:2]
    )
    raise SystemExit(1)

__version__ = "0.1.0"

"""Pytest root conftest.

The milter-side Python sources live under `milter/`. The test modules at
the repo root import them unqualified (`import primitivemail_milter`,
`from email_validator import ...`, `from store_mail import ...`), matching
what runs inside the container at `/opt/mx-box/*.py`. Prepend `milter/`
to sys.path so those imports resolve without making the milter a package
(which it isn't — it's a collection of entrypoint scripts).
"""

import sys
from pathlib import Path

_MILTER_DIR = Path(__file__).parent / "milter"
if str(_MILTER_DIR) not in sys.path:
    sys.path.insert(0, str(_MILTER_DIR))

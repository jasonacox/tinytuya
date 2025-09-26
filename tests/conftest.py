# Ensure local project root is on sys.path before any site-packages version
# so tests import the in-repo tinytuya, not an installed one.
import os, sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    # Insert at position 0 for highest precedence
    sys.path.insert(0, ROOT)

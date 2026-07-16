"""Locations of the shared, language-neutral spec artifacts.

The JSON Schema and conformance vectors live at the repository root under ``spec/`` so the
TypeScript and Python reference implementations validate against the SAME contract. Resolved
relative to this file, never the working directory.
"""

from pathlib import Path

# python/src/a_mcp/paths.py -> parents[3] is the repository root.
_REPO_ROOT = Path(__file__).resolve().parents[3]

SPEC_SCHEMA_DIR = _REPO_ROOT / 'spec' / 'schema'
SPEC_VECTORS_DIR = _REPO_ROOT / 'spec' / 'vectors'

"""Path resolution for shared spec artifacts.

Resolves absolute paths to the language-neutral JSON Schema and conformance vectors
located in the repository's `spec/` directory.
"""

from pathlib import Path

# python/src/auditable_mcp/paths.py -> parents[3] is the repository root.
_REPO_ROOT = Path(__file__).resolve().parents[3]

SPEC_SCHEMA_DIR = _REPO_ROOT / 'spec' / 'schema'
SPEC_VECTORS_DIR = _REPO_ROOT / 'spec' / 'vectors'

"""action_type vocabulary (Core Enum + ext.<vendor>.<op> hybrid).

Rules:
- Syntax: Strictly validated via regex.
- Classification: Core membership is soft. Unknown values are accepted (forward-compat).
- Effect: (mutates, egress) is orthogonal to the verb. Ambiguous types fail safe to True/True.
"""

import re

# ext form requires >= 3 segments; other forms >= 2 and must not start with the reserved ext.
ACTION_TYPE_RE = re.compile(r'^(ext(\.[a-z0-9_]+){2,}|(?!ext(\.|$))[a-z0-9_]+(\.[a-z0-9_]+)+)$')

# Core Enum v0.1 — 7 values. Queue/pubsub and compute-provisioning deliberately stay in ext.*.
CORE_ACTION_TYPES = (
    'db.read',
    'db.write',
    'fs.read',
    'fs.write',
    'api.request',
    'os.exec',
    'secret.read',
)

_CORE_SET = frozenset(CORE_ACTION_TYPES)
_BENIGN_READS = frozenset({'db.read', 'fs.read', 'secret.read'})


def is_syntactically_valid(action_type: str) -> bool:
    """Return True if ``action_type`` is a syntactically valid dotted lowercase token."""
    return ACTION_TYPE_RE.match(action_type) is not None


def is_core(action_type: str) -> bool:
    """Return True if ``action_type`` is a v0.1 Core Enum value."""
    return action_type in _CORE_SET


def is_extension(action_type: str) -> bool:
    """Return True if ``action_type`` is in the ext.* namespace."""
    return action_type.startswith('ext.')


def resolve_effect(action_type: str, mutates: bool | None, egress: bool | None) -> tuple[bool, bool]:
    """Resolve the (mutates, egress) effect against the fail-safe floor.

    Resolution order:
    1. Explicit: Honored if both flags are declared.
    2. Implicit benign: (False, False) for known read-only core types.
    3. Fail-safe: (True, True) for anything else (ext.*, api.request, unknown).

    Args:
        action_type: The action type.
        mutates: The tool's declared mutates flag, or None if undeclared.
        egress: The tool's declared egress flag, or None if undeclared.

    Returns:
        The resolved (mutates, egress) tuple.
    """
    if mutates is not None and egress is not None:
        return (mutates, egress)
    if action_type in _BENIGN_READS:
        return (mutates if mutates is not None else False, egress if egress is not None else False)
    return (mutates if mutates is not None else True, egress if egress is not None else True)

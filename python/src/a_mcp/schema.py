"""Validation against the shared JSON Schema (the cross-language contract).

The Python host validates events against the very JSON Schema the TypeScript reference
generates from its Zod source of truth. The generated schema encodes uuid/date-time as both
``format`` and ``pattern``, so structural validation here also enforces those via the pattern.
"""

import json

from jsonschema import Draft202012Validator

from a_mcp.paths import SPEC_SCHEMA_DIR

_event_schema = json.loads((SPEC_SCHEMA_DIR / 'audit-event.schema.json').read_text(encoding='utf-8'))
_event_validator = Draft202012Validator(_event_schema)


def validate_event(event: object) -> str | None:
    """Validate an event against the shared audit-event JSON Schema.

    Args:
        event: The value to validate.

    Returns:
        None if valid, otherwise the first validation error message.
    """
    error = next(iter(_event_validator.iter_errors(event)), None)
    return error.message if error is not None else None
    # end def

"""Validation against the shared JSON Schema (the cross-language contract).

The Python host validates events against the very JSON Schema the TypeScript reference
generates from its Zod source of truth. The generated schema encodes uuid/date-time as
``pattern``, so structural validation here also enforces those via the pattern.

JSON Schema patterns are ECMA-262 regular expressions. Python's ``re`` differs from them in two ways
that matter here: ``$`` also matches before a trailing newline, and ``\\d`` matches any Unicode digit.
Either would let this port accept a string the TypeScript port refuses, so patterns are evaluated with
``$`` anchored at the end of input and with ASCII classes.
"""

import json
import re
from collections.abc import Iterator
from functools import cache

from jsonschema import Draft202012Validator, ValidationError
from jsonschema.protocols import Validator
from jsonschema.validators import extend

from auditable_mcp.canonical import canonical_domain_error
from auditable_mcp.paths import SPEC_SCHEMA_DIR

# The published versions before this one, whose sealed records a verifier reads under their own
# schema (§11.4).
EARLIER_VERSIONS = ('0.1', '0.1.1', '0.2')

_UNESCAPED_DOLLAR = re.compile(r'(?<!\\)\$')


@cache
def _compile(pattern: str) -> re.Pattern[str]:
    """Compile an ECMA-262 pattern with ECMA-262's `$` and ASCII class semantics."""
    return re.compile(_UNESCAPED_DOLLAR.sub(r'\\Z', pattern), re.ASCII)


def _pattern(validator: Validator, pattern: str, instance: object, schema: dict) -> Iterator[ValidationError]:
    """The `pattern` keyword, evaluated as ECMA-262 evaluates it."""
    if validator.is_type(instance, 'string') and not _compile(pattern).search(instance):
        yield ValidationError(f'{instance!r} does not match {pattern!r}')


_EcmaValidator = extend(Draft202012Validator, {'pattern': _pattern})


def _validator(*path: str) -> Validator:
    """Load a schema from the shared spec directory."""
    return _EcmaValidator(json.loads(SPEC_SCHEMA_DIR.joinpath(*path).read_text(encoding='utf-8')))


_event_validator = _validator('audit-event.schema.json')
_attempt_response_validator = _validator('audit-attempt-response.schema.json')
_earlier_validators = {
    f'auditable-mcp/{version}': _validator('earlier', version, 'audit-event.schema.json')
    for version in EARLIER_VERSIONS
}


def _first_error(validator: Validator, value: object) -> str | None:
    """Return the first validation error message, or None."""
    error = next(iter(validator.iter_errors(value)), None)
    return error.message if error is not None else None


def validate_event(event: object) -> str | None:
    """Validate an event against the shared audit-event JSON Schema.

    Args:
        event: The value to validate.

    Returns:
        None if valid, otherwise the first validation error message.
    """
    return _first_error(_event_validator, event)


def check_event_structure(event: object) -> str | None:
    """Check structural validity (§7.1 step 1): the schema and the §8.1 canonicalization domain.

    Args:
        event: The received value.

    Returns:
        None if valid, otherwise why it is not.
    """
    return validate_event(event) or canonical_domain_error(event)


def is_earlier_version(event: object) -> bool:
    """Return True for an event of a published version before this one."""
    return isinstance(event, dict) and event.get('spec_version') in _earlier_validators


def check_sealed_event(event: object) -> str | None:
    """Check a sealed event against its own version's schema (§11.4) and the canonicalization domain.

    Args:
        event: The event of a sealed record.

    Returns:
        None if valid under its version, otherwise why it is not.
    """
    version = event.get('spec_version') if isinstance(event, dict) else None
    earlier = _earlier_validators.get(version) if isinstance(version, str) else None
    if earlier is None:
        return check_event_structure(event)
    return _first_error(earlier, event) or canonical_domain_error(event)


def validate_attempt_response(response: object) -> str | None:
    """Validate a value against the Attempt Response schema (§7.1).

    Args:
        response: The value to validate.

    Returns:
        None if valid, otherwise the first validation error message.
    """
    return _first_error(_attempt_response_validator, response)

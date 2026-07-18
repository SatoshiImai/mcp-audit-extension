"""Tests for action_type syntax validation and effect resolution."""

from auditable_mcp.action_type import is_core, is_extension, is_syntactically_valid, resolve_effect


def test_accepts_core_and_ext_tokens() -> None:
    """Core and ext dotted lowercase tokens are syntactically valid."""
    assert is_syntactically_valid('db.write')
    assert is_syntactically_valid('ext.stripe.refund_charge')
    assert is_syntactically_valid('ext.aws.s3.put_object')


def test_rejects_malformed_tokens() -> None:
    """Uppercase, whitespace, single segments, and a bare ext.<one> are rejected."""
    assert not is_syntactically_valid('DB.Write')
    assert not is_syntactically_valid('db write')
    assert not is_syntactically_valid('db')
    assert not is_syntactically_valid('ext.stripe')


def test_unknown_core_value_is_valid_but_not_core() -> None:
    """A future core value validates syntactically but is not classified as core yet."""
    assert is_syntactically_valid('cloud.provision')
    assert not is_core('cloud.provision')


def test_classifies_core_and_ext() -> None:
    """Core and ext values are classified correctly."""
    assert is_core('secret.read')
    assert is_extension('ext.iot.valve_open')
    assert not is_extension('db.read')


def test_effect_full_declaration_is_honored() -> None:
    """A full (mutates, egress) declaration is returned as-is."""
    assert resolve_effect('db.write', True, False) == (True, False)


def test_effect_benign_reads_relax() -> None:
    """Well-known non-mutating reads relax to a benign effect."""
    assert resolve_effect('db.read', None, None) == (False, False)
    assert resolve_effect('secret.read', None, None) == (False, False)


def test_effect_fail_safe_for_unknown() -> None:
    """Unknown / ext / api.request without a full declaration fail safe to mutating+egress."""
    assert resolve_effect('ext.stripe.refund_charge', None, None) == (True, True)
    assert resolve_effect('api.request', None, None) == (True, True)
    assert resolve_effect('cloud.provision', None, None) == (True, True)

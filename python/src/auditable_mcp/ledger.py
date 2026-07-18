"""Sealed records and the tamper-evident hash chain.

Local deterministic implementation of a tamper-evident append-only ledger.
A sealed record consists of the tool-emitted event plus host-assigned fields (sequence, prev_hash, record_hash).
"""

from dataclasses import dataclass

from auditable_mcp.canonical import canonicalize, sha256_hex

# The genesis link the first record chains from.
GENESIS_HASH = '0' * 64


def compute_record_hash(event: dict, seq: int, host_ts: str, prev_hash: str) -> str:
    """Compute the record hash over the committed bytes.

    Kept explicit so an independent verifier (and the Python/TypeScript ports) recompute it
    identically: ``sha256( canonical(event) | seq | host_ts | prev_hash )``.

    Args:
        event: The audit event with absent optionals already omitted.
        seq: The partition-monotonic sequence.
        host_ts: The authoritative host timestamp.
        prev_hash: The previous record hash in the chain.

    Returns:
        The hex-encoded SHA-256 record hash.
    """
    preimage = f'{canonicalize(event)}|{seq}|{host_ts}|{prev_hash}'
    return sha256_hex(preimage)


@dataclass
class SealedRecord:
    """A tool-emitted event plus the host-assigned ledger fields."""

    event: dict
    seq: int
    host_ts: str
    prev_hash: str
    record_hash: str


class Ledger:
    """Append-only, per-partition tamper-evident ledger."""

    def __init__(self, partition: str) -> None:
        """Initialize an empty ledger for the given partition."""
        self.partition = partition
        self._records: list[SealedRecord] = []

    def append(self, event: dict, host_ts: str) -> SealedRecord:
        """Append an event, assigning the next sequence and linking the hash chain."""
        seq = len(self._records)
        prev_hash = self._records[-1].record_hash if self._records else GENESIS_HASH
        record_hash = compute_record_hash(event, seq, host_ts, prev_hash)
        sealed = SealedRecord(event=event, seq=seq, host_ts=host_ts, prev_hash=prev_hash, record_hash=record_hash)
        self._records.append(sealed)
        return sealed

    def records(self) -> list[SealedRecord]:
        """Return all sealed records in append order."""
        return list(self._records)

    def digest(self) -> str:
        """Return the anchored digest (the tail record hash, or genesis if empty)."""
        return self._records[-1].record_hash if self._records else GENESIS_HASH

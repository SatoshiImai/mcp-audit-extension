"""Sealed records and the tamper-evident hash chain.

Local deterministic implementation of a tamper-evident append-only ledger.
A sealed record consists of the tool-emitted event plus host-assigned fields (seq, previous_hash, record_hash).
"""

from dataclasses import dataclass
from typing import Protocol

from auditable_mcp.canonical import canonicalize, sha256_hex


class Countersigner(Protocol):
    """Countersigns every record this host seals (§5.2, §7.1)."""

    @property
    def key_id(self) -> str:
        """The `host_key_id` a verifier's registry resolves to this host's key."""
        ...

    def sign(self, payload: str) -> str:
        """Return the base64url detached signature, without padding, over the UTF-8 bytes of `payload`."""
        ...


# The genesis link the first record chains from.
GENESIS_HASH = '0' * 64


def compute_record_hash(event: dict, seq: int, host_ts: str, previous_hash: str) -> str:
    """Compute the record hash over the RFC 8785 (JCS) canonical form of the sealed-record object.

    The preimage is a single JSON object -- never a delimiter-joined string -- so it cannot be
    forged by canonicalization tricks. Implementations build ``{event, host_ts, previous_hash, seq}``,
    canonicalize it (JCS, §8), and hash the bytes:
    ``sha256( JCS({event, host_ts, previous_hash, seq}) )``.

    Args:
        event: The audit event with absent optionals already omitted.
        seq: The partition-monotonic ledger index.
        host_ts: The authoritative host timestamp.
        previous_hash: The previous record hash in the chain.

    Returns:
        The hex-encoded SHA-256 record hash.
    """
    preimage = {'event': event, 'host_ts': host_ts, 'previous_hash': previous_hash, 'seq': seq}
    return sha256_hex(canonicalize(preimage))


def countersignature_payload(seq: int, host_ts: str, log_id: str, previous_hash: str, record_hash: str) -> str:
    """Return the bytes a countersigning host signs: its own assigned fields and the ledger's name (§7.1).

    The preimage carries no signature field, so there is no self-reference, and it is not part of the
    §8.2 record-hash preimage: a record sealed with a countersignature and the same record sealed
    without one have the same `record_hash`.
    """
    return canonicalize(
        {'host_ts': host_ts, 'log_id': log_id, 'previous_hash': previous_hash, 'record_hash': record_hash, 'seq': seq}
    )


@dataclass
class SealedRecord:
    """A tool-emitted event plus the host-assigned ledger fields.

    `host_signature`, `host_key_id`, and `log_id` appear together or not at all (§7.1). A record
    carrying them was confirmed by the host that `host_key_id` names, in the ledger `log_id` names; one
    without them is uncountersigned, which is a state and not an anomaly (§5.2).
    """

    event: dict
    seq: int
    host_ts: str
    previous_hash: str
    record_hash: str
    host_signature: str | None = None
    host_key_id: str | None = None
    log_id: str | None = None


class Ledger:
    """Append-only, per-partition tamper-evident ledger."""

    def __init__(self, partition: str, log_id: str | None = None) -> None:
        """Initialize an empty ledger for the given partition.

        `log_id` names the partition's chain in every countersignature (§7.1); it defaults to the
        partition's own name, which is stable and distinct from every other chain the host keeps.
        """
        self.partition = partition
        self.log_id = log_id if log_id is not None else partition
        self._records: list[SealedRecord] = []

    def append(self, event: dict, host_ts: str, countersigner: Countersigner | None = None) -> SealedRecord:
        """Append an event, assigning the next seq and linking the hash chain.

        §7.1 requires the assignment, the seal and the commit to be atomic with respect to any other
        record being sealed into the same partition. Nothing here awaits, so the section is the call
        itself; a host that signs or persists asynchronously holds a lock across the same span.
        """
        seq = len(self._records)
        previous_hash = self._records[-1].record_hash if self._records else GENESIS_HASH
        record_hash = compute_record_hash(event, seq, host_ts, previous_hash)
        signature = key_id = log_id = None
        if countersigner is not None:
            signature = countersigner.sign(
                countersignature_payload(seq, host_ts, self.log_id, previous_hash, record_hash)
            )
            key_id = countersigner.key_id
            log_id = self.log_id
        sealed = SealedRecord(
            event=event,
            seq=seq,
            host_ts=host_ts,
            previous_hash=previous_hash,
            record_hash=record_hash,
            host_signature=signature,
            host_key_id=key_id,
            log_id=log_id,
        )
        self._records.append(sealed)
        return sealed

    def records(self) -> list[SealedRecord]:
        """Return all sealed records in append order."""
        return list(self._records)

    def digest(self) -> str:
        """Return the anchored digest (the tail record hash, or genesis if empty)."""
        return self._records[-1].record_hash if self._records else GENESIS_HASH

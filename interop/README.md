# Interop vectors — not part of the specification

These files pin what this project's two SDK ports agree on where the specification deliberately
says nothing. They are **not normative**. An implementation that ignores them is still conformant.

## Why they exist

Spec sec. 5.1 gives a registry entry its meaning — one `key_id`, one algorithm, one public key that
MUST be a key of that algorithm — and leaves provisioning to the deployment. That is right for a
specification: a deployment that distributes keys through an existing PKI, or an LDAP directory, or
a secret manager, should not be non-conformant because a document picked a file format.

But two implementations that have to hand each other a key need one form, or the handover silently
fails — and it fails late, as `signature-invalid`, which names a forged signature and sends an
operator looking for the wrong thing.

So the form lives here: chosen by the SDKs, published so a third implementation can adopt it if it
wants to talk to them, and carrying no requirement on anyone who does not.

## What is pinned

| File | What both ports must agree on |
|---|---|
| `key-exchange.json` | The JWK Set (RFC 7517 / RFC 8037) a registry is provisioned from, the RFC 7638 thumbprints of its keys, the PKCS#8 form of a tool's private half, and the malformed documents both ports must refuse |

## These are frozen bytes

Each port reads this file and checks its own behaviour against it. Neither generates it at test
time: two implementations that each render their own answer prove only that each agrees with
itself.

The file was generated once, by the Python port, and committed. From then on it is frozen — a change
in either port that breaks the agreement fails against these bytes in both. Regenerating it is a
deliberate act, and a regeneration that changes existing entries is a breaking change to the
interchange form, not a fix.

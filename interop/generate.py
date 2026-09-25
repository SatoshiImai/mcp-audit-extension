"""Generate `key-exchange.json`. Run deliberately, not at test time; see README.md.

The key material comes from the fixed seeds recorded in the file, so a rerun reproduces it byte for
byte. A rerun that changes an existing entry is a breaking change to the interchange form, not a fix.

    cd ../auditable-mcp-sdk-python && python ../mcp-audit-extension/interop/generate.py
"""
import base64
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, derive_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from auditable_mcp.encoding import b64url_decode, b64url_encode
from auditable_mcp.l2 import KeyRegistry, KeyRole, SignatureAlgorithm, ToolKey, jwk_thumbprint, public_jwk, tool_key_pkcs8

# Fixed material so the file is reproducible from the recorded seeds, never random.
ED_SEED = bytes(range(32))
# The host's countersigning key is its own: the tool and host registries share no key (spec sec. 10.9).
HOST_ED_SEED = bytes(range(64, 96))
P256_SCALAR = int.from_bytes(bytes(range(1, 33)), 'big')

ed_private = Ed25519PrivateKey.from_private_bytes(ED_SEED)
tool = ToolKey(key_id='janus:example:ed25519:2026-09-25', public_key=ed_private.public_key(), private_key=ed_private)
p256_public = derive_private_key(P256_SCALAR, SECP256R1()).public_key()

tools = KeyRegistry(KeyRole.TOOL)
tools.register_tool_key(tool)
tools.register('odin:example:p256:2026-09-25', p256_public, SignatureAlgorithm.ES256)
hosts = KeyRegistry(KeyRole.HOST)
host_public = Ed25519PrivateKey.from_private_bytes(HOST_ED_SEED).public_key()
hosts.register('odin-host:example:ed25519:2026-09-25', host_public, SignatureAlgorithm.ED25519)

tool_set, host_set = tools.to_jwks(), hosts.to_jwks()
good = public_jwk('k', ed_private.public_key(), SignatureAlgorithm.ED25519, KeyRole.TOOL)

def without(member):
    return {k: v for k, v in good.items() if k != member}

def shortened(value):
    """The same member, validly encoded, three bytes short."""
    return b64url_encode(b64url_decode(value)[:-3])

refusals = [
    {'name': 'no-kid', 'because': 'a registry entry binds a key_id (§5.1)', 'jwk': without('kid')},
    {'name': 'empty-kid', 'because': 'a key_id is non-empty (§5.1)', 'jwk': {**good, 'kid': ''}},
    {'name': 'no-role', 'because': 'a set that names no role can be loaded into the wrong registry (§5.2)', 'jwk': without('amcp_role')},
    {'name': 'unknown-curve', 'because': 'a new algorithm arrives with a new spec_version, not in a key file (§12.1)', 'jwk': {**good, 'crv': 'Ed448'}},
    {'name': 'short-ed25519-x', 'because': 'an Ed25519 x is 32 bytes (RFC 8037)', 'jwk': {**good, 'x': shortened(good['x'])}},
    {'name': 'ed25519-x-padded', 'because': 'JWK key material is base64url without padding (RFC 7517, RFC 7515 sec. 2)', 'jwk': {**good, 'x': good['x'] + '='}},
    {'name': 'alg-contradicts-the-key', 'because': 'an `alg` present on a JWK names the algorithm the key is (RFC 7517)', 'jwk': {**good, 'alg': 'ES256'}},
    {'name': 'ed25519-x-not-base64url', 'because': 'JWK key material is base64url (RFC 7517)', 'jwk': {**good, 'x': 'not base64url!!'}},
]
p256 = public_jwk('k', p256_public, SignatureAlgorithm.ES256, KeyRole.TOOL)
refusals += [
    {'name': 'short-p256-x', 'because': 'a P-256 coordinate is 32 bytes (RFC 7518)', 'jwk': {**p256, 'x': shortened(p256['x'])}},
    {'name': 'p256-missing-y', 'because': 'a P-256 key carries both coordinates (RFC 7518)', 'jwk': {k: v for k, v in p256.items() if k != 'y'}},
    # x and y of the right length that are not a point on the curve: one port once registered this and
    # the other refused it, which is the asymmetry these vectors exist to prevent.
    {'name': 'p256-off-curve', 'because': 'two coordinates of the right length are not yet a key (RFC 7518)', 'jwk': {**p256, 'y': p256['x']}},
    {'name': 'carries-private-d', 'because': 'a registry is provisioned with public keys only; `d` is the private half', 'jwk': {**good, 'd': good['x']}},
]

# Whole documents a registry must refuse, leaving what it already held untouched.
other = public_jwk('dup', Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64))).public_key(), SignatureAlgorithm.ED25519, KeyRole.TOOL)
twin = public_jwk('dup', ed_private.public_key(), SignatureAlgorithm.ED25519, KeyRole.TOOL)
refused_sets = [
    {'name': 'not-a-set', 'because': 'a JWK Set carries its keys under `keys` (RFC 7517)', 'jwks': {'kty': 'OKP'}},
    {'name': 'non-object-member', 'because': 'every member of `keys` is a JWK object; skipping one would load a set that is not what it claims', 'jwks': {'keys': ['not a key', good]}},
    {'name': 'kid-bound-twice', 'because': 'one key_id binds exactly one key (§10.9)', 'jwks': {'keys': [good, other, twin]}},
]

# RFC 7638 needs every required member; a thumbprint of an incomplete key names nothing.
refused_thumbprints = [
    {'name': 'okp-missing-x', 'jwk': {'kty': 'OKP', 'crv': 'Ed25519'}},
    {'name': 'ec-missing-y', 'jwk': {'kty': 'EC', 'crv': 'P-256', 'x': p256['x']}},
]

document = {
    'note': (
        'Frozen interop vectors for the SDK key-exchange form. Not part of the specification; see '
        'interop/README.md. Each port READS this file - neither renders its own answer and compares.'
    ),
    'seeds': {
        'ed25519_private_key_seed_hex': ED_SEED.hex(),
        'host_ed25519_private_key_seed_hex': HOST_ED_SEED.hex(),
        'p256_private_scalar_hex': format(P256_SCALAR, '064x'),
        'note': 'Recorded so the file can be reproduced, not so an implementation derives it at test time.',
    },
    'tool_jwks': tool_set,
    'host_jwks': host_set,
    'thumbprints': {
        jwk['kid']: jwk_thumbprint(jwk) for jwk in [*tool_set['keys'], *host_set['keys']]
    },
    'private_keys': [
        {
            'kid': tool.key_id,
            'pkcs8_base64': base64.b64encode(tool_key_pkcs8(tool)).decode('ascii'),
            # The same key as PEM, which is how a secret manager usually hands one over.
            'pkcs8_pem': '-----BEGIN PRIVATE KEY-----\n'
            + base64.b64encode(tool_key_pkcs8(tool)).decode('ascii')
            + '\n-----END PRIVATE KEY-----\n',
            'public_jwk_thumbprint': jwk_thumbprint(public_jwk(tool.key_id, tool.public_key, SignatureAlgorithm.ED25519, KeyRole.TOOL)),
        }
    ],
    'refused_jwks': refusals,
    'refused_jwks_sets': refused_sets,
    'refused_thumbprints': refused_thumbprints,
    'role_mismatch': {
        'because': 'a tool key held as a host’s lets a tool sign itself into the countersigned state (§5.2)',
        'load_into_role': 'host',
        'jwks': tool_set,
    },
}
path = str(Path(__file__).with_name('key-exchange.json'))
with open(path, 'w', encoding='utf-8') as handle:
    json.dump(document, handle, indent=2, sort_keys=False, ensure_ascii=False)
    handle.write('\n')
print('wrote', path)

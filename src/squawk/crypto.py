"""The cryptographic operations squawk uses, in one place.

Signing is ed25519, key agreement is x25519, keys are derived with
HKDF-SHA256, and messages are encrypted with XChaCha20-Poly1305 (the IETF
variant with a 24-byte nonce, ciphertext followed by the 16-byte tag). Every
squawk peer must produce the same bytes, so these choices are fixed.
"""

import hashlib
import hmac
import os

import nacl.bindings
import nacl.signing


def random_bytes(length: int) -> bytes:
    """`length` random bytes from the operating system."""
    return os.urandom(length)


def ed25519_random_secret_key() -> bytes:
    """A new random 32-byte ed25519 secret key."""
    return os.urandom(32)


def ed25519_public_key(secret_key: bytes) -> bytes:
    """The ed25519 public key for a 32-byte secret key."""
    return bytes(nacl.signing.SigningKey(secret_key).verify_key)


def ed25519_sign(message: bytes, secret_key: bytes) -> bytes:
    """The 64-byte ed25519 signature of `message` by the 32-byte secret key."""
    return nacl.signing.SigningKey(secret_key).sign(message).signature


def ed25519_verify(signature: bytes, message: bytes, public_key: bytes) -> bool:
    """True when `signature` is a valid signature of `message` by `public_key`.

    Any problem with the inputs (wrong lengths, a key that is not a valid
    point) counts as not valid rather than raising.
    """
    try:
        nacl.signing.VerifyKey(public_key).verify(message, signature)
    except Exception:
        return False
    return True


def ed25519_public_to_x25519(public_key: bytes) -> bytes:
    """The x25519 public key that corresponds to an ed25519 public key."""
    return nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(public_key)


def ed25519_secret_to_x25519(secret_key: bytes) -> bytes:
    """The x25519 secret key that corresponds to a 32-byte ed25519 secret key.

    This is the first half of SHA-512 of the secret key, clamped.
    """
    public_key = ed25519_public_key(secret_key)
    # libsodium wants the 64-byte form: the secret key followed by the public key.
    return nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(secret_key + public_key)


def x25519_public_key(secret_key: bytes) -> bytes:
    """The x25519 public key for a 32-byte x25519 secret key."""
    return nacl.bindings.crypto_scalarmult_base(secret_key)


def x25519_shared_secret(secret_key: bytes, public_key: bytes) -> bytes:
    """The x25519 shared secret of our secret key and their public key.

    Raises if the result is all zeros (their key has small order).
    """
    return nacl.bindings.crypto_scalarmult(secret_key, public_key)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF with SHA-256 (RFC 5869): extract, then expand to `length` bytes."""
    if length > 255 * 32:
        raise ValueError("HKDF-SHA256 cannot produce more than 8160 bytes")
    prk = hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()
    output = b""
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        output += block
        counter += 1
    return output[:length]


def xchacha20poly1305_encrypt(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    """Encrypts with XChaCha20-Poly1305; returns the ciphertext followed by the tag."""
    return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)


def xchacha20poly1305_decrypt(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    """Decrypts and checks XChaCha20-Poly1305; raises if anything was changed."""
    return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, aad, nonce, key)

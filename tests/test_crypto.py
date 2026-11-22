"""Checks of the building blocks against published test vectors."""

import hashlib

from squawk.crypto import (
    ed25519_public_key,
    ed25519_public_to_x25519,
    ed25519_secret_to_x25519,
    ed25519_sign,
    hkdf_sha256,
    x25519_public_key,
    xchacha20poly1305_decrypt,
    xchacha20poly1305_encrypt,
)


def test_hkdf_sha256_matches_rfc_5869_test_case_1() -> None:
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    okm = hkdf_sha256(ikm, salt, info, 42)
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )


def test_hkdf_sha256_matches_rfc_5869_test_case_3_with_no_salt_or_info() -> None:
    okm = hkdf_sha256(bytes.fromhex("0b" * 22), b"", b"", 42)
    assert okm.hex() == (
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    )


def test_ed25519_matches_rfc_8032_test_1() -> None:
    secret = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    public = ed25519_public_key(secret)
    assert public.hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    assert ed25519_sign(b"", secret).hex() == (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e3970"
        "1cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )


def test_x25519_secret_is_the_clamped_first_half_of_sha512_of_the_ed25519_secret() -> None:
    secret = bytes(range(32))
    expected = bytearray(hashlib.sha512(secret).digest()[:32])
    expected[0] &= 248
    expected[31] &= 127
    expected[31] |= 64
    x_secret = ed25519_secret_to_x25519(secret)
    assert x_secret == bytes(expected)
    # And the two derived halves are a matching x25519 key pair.
    assert x25519_public_key(x_secret) == ed25519_public_to_x25519(ed25519_public_key(secret))


def test_xchacha20poly1305_matches_the_draft_irtf_cfrg_xchacha_test_vector() -> None:
    # draft-irtf-cfrg-xchacha-03, appendix A.3.1.
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the "
        b"future, sunscreen would be it."
    )
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    key = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    nonce = bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657")
    sealed = xchacha20poly1305_encrypt(key, nonce, aad, plaintext)
    assert sealed[-16:].hex() == "c0875924c1c7987947deafd8780acf49"
    assert sealed[:16].hex() == "bd6d179d3e83d43b9576579493c0e939"
    assert xchacha20poly1305_decrypt(key, nonce, aad, sealed) == plaintext

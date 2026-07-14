"""Deterministic KAT-style tests for the Python binding."""

from hashlib import sha256

from py_fn_dsa import (
    HASH_ID_RAW,
    LOGN_1024,
    LOGN_512,
    SigningKey,
    VerifyKey,
    ffi,
    lib,
    verify,
)


def _sign_key_size(logn: int) -> int:
    indicators = sum(logn >= threshold for threshold in (6, 8, 10))
    return 1 + ((12 - indicators) << (logn - 2))


def _vrfy_key_size(logn: int) -> int:
    return 1 + (7 << (logn - 2))


def _signature_size(logn: int) -> int:
    shift = 10 - logn
    return (
        44
        + 3 * (256 >> shift)
        + 2 * (128 >> shift)
        + 3 * (64 >> shift)
        + 2 * (16 >> shift)
        - 2 * (2 >> shift)
        - 8 * (1 >> shift)
    )


def _key_material_from_seed(logn: int, seed: bytes) -> tuple[VerifyKey, SigningKey]:
    sign_key = ffi.new(f"unsigned char[{_sign_key_size(logn)}]")
    vrfy_key = ffi.new(f"unsigned char[{_vrfy_key_size(logn)}]")
    lib.fndsa_keygen_seeded(logn, seed, len(seed), sign_key, vrfy_key)
    return (
        VerifyKey(logn, bytes(ffi.buffer(vrfy_key))),
        SigningKey(logn, bytes(ffi.buffer(sign_key))),
    )


def _signature_from_seed(signing_key: SigningKey, message: bytes, context: bytes, seed: bytes) -> bytes:
    signature = ffi.new(f"unsigned char[{_signature_size(signing_key.logn)}]")
    sig_len = lib.fndsa_sign_seeded(
        signing_key.key_data,
        len(signing_key.key_data),
        context,
        len(context),
        HASH_ID_RAW,
        message,
        len(message),
        seed,
        len(seed),
        signature,
        _signature_size(signing_key.logn),
    )
    return bytes(ffi.buffer(signature, sig_len))


def test_seeded_keygen_kat_512():
    verify_key, signing_key = _key_material_from_seed(LOGN_512, b"kat-keygen-512")
    digest = sha256(signing_key.key_data + verify_key.key_data).hexdigest()
    assert digest == "8d7e3effadf37640f2b7abe1341089a0baa9b66414ad07d07a652c67c1b8963f"


def test_seeded_keygen_kat_1024():
    verify_key, signing_key = _key_material_from_seed(LOGN_1024, b"kat-keygen-1024")
    digest = sha256(signing_key.key_data + verify_key.key_data).hexdigest()
    assert digest == "57077b36fe50ba4960fc4939e71a933313a684084b0e3022fc42440e3c0ba588"


def test_seeded_sign_kat_512():
    verify_key, signing_key = _key_material_from_seed(LOGN_512, b"kat-sign-key-512")
    message = b"kat-message-512"
    context = b"kat-context"
    signature = _signature_from_seed(signing_key, message, context, b"kat-sign-seed")
    assert len(signature) == 666
    assert sha256(signature).hexdigest() == "b57c35d42e3641d49acc8a2d129facab91f9ddc883c76f8e65fcaf6d9d5bfbca"
    assert verify(verify_key, signature, message, context=context) is True


def test_seeded_sign_kat_1024():
    verify_key, signing_key = _key_material_from_seed(LOGN_1024, b"kat-sign-key-1024")
    message = b"kat-message-1024"
    context = b"kat-context"
    signature = _signature_from_seed(signing_key, message, context, b"kat-sign-seed")
    assert len(signature) == 1280
    assert sha256(signature).hexdigest() == "56e1a5f81732e0f7ba88fac29decb6ff108754cda6fcc2231474909e7eb0417c"
    assert verify(verify_key, signature, message, context=context) is True
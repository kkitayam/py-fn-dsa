"""Cross-language interoperability tests for Python and CFFI APIs."""

from py_fn_dsa import (
    HASH_ID_RAW,
    LOGN_1024,
    LOGN_512,
    SigningKey,
    VerifyKey,
    ffi,
    lib,
    sign,
    verify,
)


def _sign_key_size(logn: int) -> int:
    indicators = sum(logn >= threshold for threshold in (6, 8, 10))
    return 65 + ((12 - indicators) << (logn - 2))


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


def _key_material_from_c_seed(logn: int, seed: bytes) -> tuple[VerifyKey, SigningKey]:
    sign_key = ffi.new(f"unsigned char[{_sign_key_size(logn)}]")
    vrfy_key = ffi.new(f"unsigned char[{_vrfy_key_size(logn)}]")
    lib.fndsa_keygen_seeded(logn, seed, len(seed), sign_key, vrfy_key)
    return (
        VerifyKey(logn, bytes(ffi.buffer(vrfy_key))),
        SigningKey(logn, bytes(ffi.buffer(sign_key))),
    )


def _c_signature(signing_key: SigningKey, message: bytes, context: bytes, seed: bytes) -> bytes:
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


def _c_verify(verify_key: VerifyKey, signature: bytes, message: bytes, context: bytes) -> bool:
    return bool(
        lib.fndsa_verify(
            signature,
            len(signature),
            verify_key.key_data,
            len(verify_key.key_data),
            context,
            len(context),
            HASH_ID_RAW,
            message,
            len(message),
        )
    )


def test_python_signatures_verify_with_c_and_python_512():
    verify_key, signing_key = _key_material_from_c_seed(LOGN_512, b"cross-language-key-512")
    message = b"cross-language-message-512"
    context = b"interop"

    python_signature = sign(signing_key, message, context=context)
    assert verify(verify_key, python_signature, message, context=context) is True
    assert _c_verify(verify_key, python_signature, message, context) is True

    c_signature = _c_signature(signing_key, message, context, b"cross-language-sign-512")
    assert verify(verify_key, c_signature, message, context=context) is True
    assert _c_verify(verify_key, c_signature, message, context) is True


def test_python_signatures_verify_with_c_and_python_1024():
    verify_key, signing_key = _key_material_from_c_seed(LOGN_1024, b"cross-language-key-1024")
    message = b"cross-language-message-1024"
    context = b"interop"

    python_signature = sign(signing_key, message, context=context)
    assert verify(verify_key, python_signature, message, context=context) is True
    assert _c_verify(verify_key, python_signature, message, context) is True

    c_signature = _c_signature(signing_key, message, context, b"cross-language-sign-1024")
    assert verify(verify_key, c_signature, message, context=context) is True
    assert _c_verify(verify_key, c_signature, message, context) is True
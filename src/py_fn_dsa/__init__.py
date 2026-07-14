"""Python bindings for c-fn-dsa."""

from ._c_fn_dsa import lib, ffi

__version__ = "0.1.0"

__all__ = [
    "HASH_ID_RAW",
    "HASH_ID_SHA256",
    "HASH_ID_SHA384",
    "HASH_ID_SHA512",
    "HASH_ID_SHA512_256",
    "HASH_ID_SHA3_256",
    "HASH_ID_SHA3_384",
    "HASH_ID_SHA3_512",
    "HASH_ID_SHAKE128",
    "HASH_ID_SHAKE256",
    "LOGN_512",
    "LOGN_1024",
    "SigningKey",
    "VerifyKey",
    "keygen",
    "sign",
    "verify",
]

# Hash function identifiers (DER-encoded ASN.1 OIDs)
HASH_ID_RAW = b""  # Raw message (no pre-hashing)
HASH_ID_SHA256 = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01"
HASH_ID_SHA384 = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02"
HASH_ID_SHA512 = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03"
HASH_ID_SHA512_256 = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x06"
HASH_ID_SHA3_256 = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x08"
HASH_ID_SHA3_384 = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x09"
HASH_ID_SHA3_512 = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0A"
HASH_ID_SHAKE128 = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0B"
HASH_ID_SHAKE256 = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0C"

# Standard degrees
LOGN_512 = 9   # Level I (~128 bits)
LOGN_1024 = 10  # Level V (~256 bits)


class SigningKey:
    """FN-DSA signing key."""

    def __init__(self, logn: int, key_data: bytes):
        if not 2 <= logn <= 10:
            raise ValueError(f"logn must be 2-10, got {logn}")
        self.logn = logn
        self.key_data = bytes(key_data)

    @staticmethod
    def from_bytes(logn: int, key_data: bytes) -> 'SigningKey':
        return SigningKey(logn, key_data)


class VerifyKey:
    """FN-DSA verifying key."""

    def __init__(self, logn: int, key_data: bytes):
        if not 2 <= logn <= 10:
            raise ValueError(f"logn must be 2-10, got {logn}")
        self.logn = logn
        self.key_data = bytes(key_data)

    @staticmethod
    def from_bytes(logn: int, key_data: bytes) -> 'VerifyKey':
        return VerifyKey(logn, key_data)


def keygen(logn: int = LOGN_1024) -> tuple[VerifyKey, SigningKey]:
    """Generate a new key pair."""
    if not 2 <= logn <= 10:
        raise ValueError(f"logn must be 2-10, got {logn}")

    sign_key_size = _calc_sign_key_size(logn)
    vrfy_key_size = _calc_vrfy_key_size(logn)

    sign_key_buf = ffi.new(f"unsigned char[{sign_key_size}]")
    vrfy_key_buf = ffi.new(f"unsigned char[{vrfy_key_size}]")

    result = lib.fndsa_keygen(logn, sign_key_buf, vrfy_key_buf)
    if result == 0:
        raise RuntimeError(f"Failed to generate key pair for logn={logn}")

    signing_key = SigningKey(logn, bytes(ffi.buffer(sign_key_buf)[:]))
    verify_key = VerifyKey(logn, bytes(ffi.buffer(vrfy_key_buf)[:]))
    return verify_key, signing_key


def sign(signing_key: SigningKey, message: bytes,
         context: bytes = b'', hash_id: bytes = HASH_ID_RAW) -> bytes:
    """Sign a message.
    
    Args:
        signing_key: SigningKey with signing key
        message: Raw message or pre-hashed message
        context: Domain separation context (at most 255 bytes)
        hash_id: Hash function identifier (default: HASH_ID_RAW for raw message)
        
    Returns:
        Signature bytes
        
    Raises:
        RuntimeError: If signing fails
        ValueError: If inputs are invalid
    """
    if not isinstance(signing_key, SigningKey):
        raise TypeError("signing_key must be SigningKey")
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    if not isinstance(context, bytes):
        raise TypeError("context must be bytes")
    if len(context) > 255:
        raise ValueError("context must be at most 255 bytes")
    
    max_sig_size = _calc_signature_size(signing_key.logn)
    
    # Prepare buffers
    sign_key_buf = ffi.new(f"unsigned char[{len(signing_key.key_data)}]", signing_key.key_data)
    ctx_buf = ffi.new(f"unsigned char[{len(context)}]", context) if context else ffi.NULL
    msg_buf = ffi.new(f"unsigned char[{len(message)}]", message) if message else ffi.NULL
    sig_buf = ffi.new(f"unsigned char[{max_sig_size}]")
    
    # Hash ID as C string
    hash_id_cstr = ffi.new("char[]", bytes(hash_id) + b"\0")
    
    # Call C function
    sig_len = lib.fndsa_sign(
        sign_key_buf, len(signing_key.key_data),
        ctx_buf, len(context),
        hash_id_cstr,
        msg_buf, len(message),
        sig_buf, max_sig_size
    )
    
    if sig_len == 0:
        raise RuntimeError("Failed to sign message")
    
    return bytes(ffi.buffer(sig_buf, sig_len)[:])


def verify(verify_key: VerifyKey, signature: bytes, message: bytes, 
           context: bytes = b'', hash_id: bytes = HASH_ID_RAW) -> bool:
    """Verify a signature.
    
    Args:
        verify_key: VerifyKey with verifying key
        signature: Signature bytes
        message: Raw message or pre-hashed message
        context: Domain separation context
        hash_id: Hash function identifier (must match signing)
        
    Returns:
        True if signature is valid, False otherwise
        
    Raises:
        ValueError: If inputs are invalid
    """
    if not isinstance(verify_key, VerifyKey):
        raise TypeError("verify_key must be VerifyKey")
    if not isinstance(signature, bytes):
        raise TypeError("signature must be bytes")
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    if not isinstance(context, bytes):
        raise TypeError("context must be bytes")
    if len(context) > 255:
        raise ValueError("context must be at most 255 bytes")
    
    # Prepare buffers
    sig_buf = ffi.new(f"unsigned char[{len(signature)}]", signature)
    vrfy_key_buf = ffi.new(f"unsigned char[{len(verify_key.key_data)}]", verify_key.key_data)
    ctx_buf = ffi.new(f"unsigned char[{len(context)}]", context) if context else ffi.NULL
    msg_buf = ffi.new(f"unsigned char[{len(message)}]", message) if message else ffi.NULL
    
    # Hash ID as C string
    hash_id_cstr = ffi.new("char[]", bytes(hash_id) + b"\0")
    
    # Call C function
    result = lib.fndsa_verify(
        sig_buf, len(signature),
        vrfy_key_buf, len(verify_key.key_data),
        ctx_buf, len(context),
        hash_id_cstr,
        msg_buf, len(message)
    )
    
    return result != 0


def _calc_sign_key_size(logn: int) -> int:
    """Calculate signing key size for given logn.
    
    Formula from fndsa.h:
    FNDSA_SIGN_KEY_SIZE(logn) = 1 + ((12 - indicators) << (logn - 2))
    where indicators = (logn>=6) + (logn>=8) + (logn>=10)
    """
    indicators = sum([logn >= n for n in [6, 8, 10]])
    return 1 + ((12 - indicators) << (logn - 2))


def _calc_vrfy_key_size(logn: int) -> int:
    """Calculate verifying key size for given logn.
    
    Formula from fndsa.h:
    FNDSA_VRFY_KEY_SIZE(logn) = 1 + (7 << (logn - 2))
    """
    return 1 + (7 << (logn - 2))


def _calc_signature_size(logn: int) -> int:
    """Calculate signature size for given logn.
    
    Formula from fndsa.h:
    FNDSA_SIGNATURE_SIZE(logn) = 44 + 3*(256>>(10-logn)) + 2*(128>>(10-logn))
                                   + 3*(64>>(10-logn)) + 2*(16>>(10-logn))
                                   - 2*(2>>(10-logn)) - 8*(1>>(10-logn))
    """
    shift = 10 - logn
    return (44 +
            3 * (256 >> shift) +
            2 * (128 >> shift) +
            3 * (64 >> shift) +
            2 * (16 >> shift) -
            2 * (2 >> shift) -
            8 * (1 >> shift))


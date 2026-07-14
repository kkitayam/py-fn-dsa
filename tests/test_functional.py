"""Basic functional tests for py-fn-dsa."""

import pytest
from py_fn_dsa import LOGN_512, LOGN_1024, keygen, sign, verify


class TestKeygen:
    """Test key generation."""

    def test_keygen_standard_degrees(self):
        """Test key generation for standard degrees."""
        for logn in [LOGN_512, LOGN_1024]:
            verify_key, signing_key = keygen(logn)
            assert verify_key.logn == logn
            assert signing_key.logn == logn
            assert len(signing_key.key_data) > 0
            assert len(verify_key.key_data) > 0

    def test_keygen_invalid_degree(self):
        """Test that invalid degrees raise ValueError."""
        with pytest.raises(ValueError):
            keygen(1)
        with pytest.raises(ValueError):
            keygen(11)

    def test_keygen_weak_degrees(self):
        """Test key generation for weak degrees (testing only)."""
        for logn in range(2, 9):
            verify_key, signing_key = keygen(logn)
            assert verify_key.logn == logn
            assert signing_key.logn == logn


class TestSignVerify:
    """Test signing and verification."""

    def test_sign_verify_basic(self):
        """Test basic signing and verification."""
        verify_key, signing_key = keygen(LOGN_1024)
        message = b"Hello, FN-DSA!"
        
        # Sign
        sig = sign(signing_key, message)
        assert isinstance(sig, bytes)
        assert len(sig) > 0
        
        # Verify
        assert verify(verify_key, sig, message) is True
        
        # Verify fails with tampered message
        tampered = message[:-1] + b"X"
        assert verify(verify_key, sig, tampered) is False

    def test_sign_verify_with_context(self):
        """Test signing with domain separation context."""
        verify_key, signing_key = keygen(LOGN_1024)
        message = b"Hello, FN-DSA!"
        context = b"myapp:v1"
        
        sig = sign(signing_key, message, context=context)
        assert verify(verify_key, sig, message, context=context) is True
        
        # Verify fails with different context
        assert verify(verify_key, sig, message, context=b"different") is False
        
        # Verify fails without context
        assert verify(verify_key, sig, message) is False

    def test_sign_verify_empty_message(self):
        """Test signing empty message."""
        verify_key, signing_key = keygen(LOGN_1024)
        message = b""
        
        sig = sign(signing_key, message)
        assert verify(verify_key, sig, message) is True

    def test_sign_invalid_inputs(self):
        """Test that invalid inputs raise appropriate errors."""
        _, signing_key = keygen(LOGN_1024)
        
        # Invalid message type
        with pytest.raises(TypeError):
            sign(signing_key, "not bytes")
        
        # Invalid context type
        with pytest.raises(TypeError):
            sign(signing_key, b"msg", context="not bytes")
        
        # Context too long
        with pytest.raises(ValueError):
            sign(signing_key, b"msg", context=b"x" * 256)

    def test_verify_invalid_inputs(self):
        """Test that verify with invalid inputs raises appropriate errors."""
        verify_key, _ = keygen(LOGN_1024)
        
        # Invalid signature type
        with pytest.raises(TypeError):
            verify(verify_key, "not bytes", b"msg")
        
        # Invalid message type
        with pytest.raises(TypeError):
            verify(verify_key, b"sig", "not bytes")
        
        # Invalid context type
        with pytest.raises(TypeError):
            verify(verify_key, b"sig", b"msg", context="not bytes")

    def test_multiple_signatures(self):
        """Test that multiple signatures are different."""
        verify_key, signing_key = keygen(LOGN_1024)
        message = b"Test message"
        
        sig1 = sign(signing_key, message)
        sig2 = sign(signing_key, message)
        
        # Signatures should be different (due to randomness in signing)
        # Note: This is probabilistic; extremely unlikely to be equal
        assert sig1 != sig2
        
        # But both should verify
        assert verify(verify_key, sig1, message)
        assert verify(verify_key, sig2, message)


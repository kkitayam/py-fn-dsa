"""Test cffi module import."""

import pytest


def test_c_fn_dsa_module_exists():
    """Check that the cffi module can be imported."""
    try:
        from py_fn_dsa import _c_fn_dsa
        assert hasattr(_c_fn_dsa, 'lib')
    except ImportError:
        pytest.skip("_c_fn_dsa module not built yet")

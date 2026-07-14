"""cffi interface definitions for c-fn-dsa."""

from __future__ import annotations

from pathlib import Path

from cffi import FFI

ffi = FFI()

# Define only the function signatures needed for Python binding
ffi.cdef("""
    /* Key generation */
    int fndsa_keygen(unsigned logn, void *sign_key, void *vrfy_key);
    int fndsa_keygen_temp(unsigned logn, void *sign_key, void *vrfy_key,
                          void *tmp, size_t tmp_len);
    void fndsa_keygen_seeded(unsigned logn, const void *seed, size_t seed_len,
                            void *sign_key, void *vrfy_key);
    int fndsa_keygen_seeded_temp(unsigned logn,
                                const void *seed, size_t seed_len, 
                                void *sign_key, void *vrfy_key,
                                void *tmp, size_t tmp_len);

    /* Signing */
    size_t fndsa_sign(const void *sign_key, size_t sign_key_len,
                    const void *ctx, size_t ctx_len,
                    const char *id, const void *hv, size_t hv_len,
                    void *sig, size_t max_sig_len);
    size_t fndsa_sign_seeded(const void *sign_key, size_t sign_key_len,
                            const void *ctx, size_t ctx_len,
                            const char *id, const void *hv, size_t hv_len,
                            const void *seed, size_t seed_len,
                            void *sig, size_t max_sig_len);
    size_t fndsa_sign_temp(const void *sign_key, size_t sign_key_len,
                          const void *ctx, size_t ctx_len,
                          const char *id, const void *hv, size_t hv_len,
                          void *sig, size_t max_sig_len,
                          void *tmp, size_t tmp_len);
    size_t fndsa_sign_seeded_temp(const void *sign_key, size_t sign_key_len,
                                const void *ctx, size_t ctx_len,
                                const char *id, const void *hv, size_t hv_len,
                                const void *seed, size_t seed_len,
                                void *sig, size_t max_sig_len,
                                void *tmp, size_t tmp_len);
    
    /* Weak versions for testing */
    size_t fndsa_sign_weak(const void *sign_key, size_t sign_key_len,
                          const void *ctx, size_t ctx_len,
                          const char *id, const void *hv, size_t hv_len,
                          void *sig, size_t max_sig_len);
    size_t fndsa_sign_weak_seeded(const void *sign_key, size_t sign_key_len,
                                const void *ctx, size_t ctx_len,
                                const char *id, const void *hv, size_t hv_len,
                                const void *seed, size_t seed_len,
                                void *sig, size_t max_sig_len);
    size_t fndsa_sign_weak_temp(const void *sign_key, size_t sign_key_len,
                              const void *ctx, size_t ctx_len,
                              const char *id, const void *hv, size_t hv_len,
                              void *sig, size_t max_sig_len,
                              void *tmp, size_t tmp_len);
    size_t fndsa_sign_weak_seeded_temp(const void *sign_key, size_t sign_key_len,
                                      const void *ctx, size_t ctx_len,
                                      const char *id, const void *hv, size_t hv_len,
                                      const void *seed, size_t seed_len,
                                      void *sig, size_t max_sig_len,
                                      void *tmp, size_t tmp_len);

    /* Verification */
    int fndsa_verify(const void *sig, size_t sig_len,
                    const void *vrfy_key, size_t vrfy_key_len,
                    const void *ctx, size_t ctx_len,
                    const char *id, const void *hv, size_t hv_len);
    int fndsa_verify_weak(const void *sig, size_t sig_len,
                        const void *vrfy_key, size_t vrfy_key_len,
                        const void *ctx, size_t ctx_len,
                        const char *id, const void *hv, size_t hv_len);
    int fndsa_verify_temp(const void *sig, size_t sig_len,
                        const void *vrfy_key, size_t vrfy_key_len,
                        const void *ctx, size_t ctx_len,
                        const char *id, const void *hv, size_t hv_len,
                        void *tmp, size_t tmp_len);
    int fndsa_verify_weak_temp(const void *sig, size_t sig_len,
                              const void *vrfy_key, size_t vrfy_key_len,
                              const void *ctx, size_t ctx_len,
                              const char *id, const void *hv, size_t hv_len,
                              void *tmp, size_t tmp_len);
""")

SOURCE_FILENAMES = [
    "codec.c",
    "mq.c",
    "sha3.c",
    "sysrng.c",
    "util.c",
    "kgen.c",
    "kgen_fxp.c",
    "kgen_gauss.c",
    "kgen_mp31.c",
    "kgen_ntru.c",
    "kgen_poly.c",
    "kgen_zint31.c",
    "sign.c",
    "sign_core.c",
    "sign_fpoly.c",
    "sign_fpr.c",
    "sign_sampler.c",
    "vrfy.c",
]


def _configure_source(root: Path) -> None:
    vendor_dir = (root / "vendor" / "c-fn-dsa").resolve()
    source_files = [str(vendor_dir / name) for name in SOURCE_FILENAMES]

    ffi.set_source(
        "py_fn_dsa._c_fn_dsa",
        """
        #include "fndsa.h"
        """,
        include_dirs=[str(vendor_dir)],
        sources=source_files,
    )


def build_extension(project_root: str | Path | None = None) -> str:
    """Compile the cffi extension into the package directory."""
    root = Path(project_root) if project_root is not None else Path(__file__).resolve().parents[2]
    _configure_source(root)
    output = ffi.compile(tmpdir=str(root / "src"), verbose=True)
    return str(Path(output).resolve())


if __name__ == "__main__":
    build_extension()

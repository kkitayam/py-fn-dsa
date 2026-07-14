# py-fn-dsa

Python bindings for Thomas Pornin's [c-fn-dsa](https://github.com/pornin/c-fn-dsa) using **CFFI out-of-line API mode**.

## Features
- Thin wrapper around upstream [c-fn-dsa](https://github.com/pornin/c-fn-dsa)
- Windows and Linux support
- Pythonic API
- Upstream validation, KAT, and interoperability tests

## Installation
```sh
uv sync
```

## Quick Start
```python
from py_fn_dsa import keygen, sign, verify
vk, sk = keygen()
sig = sign(sk, b"hello")
assert verify(vk, sig, b"hello")
```

## API Reference
- keygen()
- sign()
- verify()

## Security Notes
Uses the upstream implementation without modifying cryptographic algorithms.

## Development
```sh
uv sync
uv run pytest
```

## Acknowledgements
- Thomas Pornin and the [c-fn-dsa](https://github.com/pornin/c-fn-dsa) project.


## License

MIT

# Contributing

Thanks for your interest. This project grew out of real-world needs at a
handful of commercial office buildings — contributions that add support for
protocols and vendors encountered in other buildings are especially welcome.

## Getting set up

```bash
git clone https://github.com/jamesccupps/HVAC-Network-Scanner.git
cd HVAC-Network-Scanner
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

Target Python version is **3.10+**. CI runs on 3.10, 3.11, 3.12, and 3.13 on
both Ubuntu and Windows.

## Running tests

```bash
pytest                   # full suite
pytest tests/test_codec.py -v
pytest --cov=hvac_scanner --cov-report=html
```

Tests live under `tests/` and follow the pattern `test_<module>.py`. The
codec tests use hand-constructed byte fixtures — no live network required,
no mocking. This is deliberate: the point of splitting the codec out as a
pure-function module was so the parser could be exercised against real
packet bytes.

## Code style

- Standard library only for runtime code (no numpy, requests, etc.).
- Use `logging` at module level (`log = logging.getLogger(__name__)`),
  not `print`. User-facing progress goes through the callback.
- Wrap every socket in either `contextlib.closing(...)` or a
  try/finally. No exceptions.
- No bare `except:` blocks. Catch specific exception types and log at
  DEBUG level.
- Type-annotate new public APIs. Internal helpers are fine without.

## Adding vendor support

If you've run the scanner against a new vendor or model and it wasn't
identified correctly, the ideal contribution is:

1. A new fingerprint branch in `hvac_scanner/fingerprint.py` that
   recognizes the model.
2. A test in `tests/test_fingerprint.py` that covers the new logic.
3. The `BACnet vendor ID` and any telltale service-port characteristics
   (banner strings, server headers) that drive the identification,
   documented in a code comment.

If you can include a redacted packet capture or a synthesized `IAmDevice`
dict reproducing the pattern, even better.

## Adding protocol support

See `docs/ARCHITECTURE.md` for the module template. The short version:

- New scanner module under `hvac_scanner/`
- `scan_network()` entry point with `callback` and `stop_event` parameters
- A scan pass in `ScanEngine` that calls it
- CLI flag + GUI checkbox
- Tests for any parser logic

## Responsible disclosure

If you find a protocol-level vulnerability that affects building-automation
systems (default-credentials discoveries that aren't already in vendor docs,
authentication bypass, etc.), please email the maintainer directly rather
than opening a public issue. GitHub issues are fine for everything else.

## Licensing

By submitting a PR, you agree your contribution is licensed under the MIT
license of the project.

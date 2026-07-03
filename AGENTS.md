# AGENTS.md — Guide for Coding Agents and Contributors

TinyTuya is a Python library to control Tuya-based WiFi smart devices over the local network, plus a Tuya Cloud client, network scanner, setup wizard, and CLI. Read [DESIGN.md](DESIGN.md) for the architecture before changing core code, and [PROTOCOL.md](PROTOCOL.md) before touching anything on the wire path.

## Quick Facts

- **Language/support**: Python 3.7–3.12 (the CI matrix). Do not use syntax newer than 3.7 (no walrus in hot paths reviewed for 3.7, no `match`, no 3.8+-only typing). Python 2 shims (`IS_PY2`, `from __future__`) are dead code — do not extend them; removing them is welcome.
- **Version source of truth**: `version_tuple` in `tinytuya/core/core.py`. Bump only as part of a release, together with a `RELEASE.md` entry.
- **Dependencies**: `requests`, `colorama`, and exactly one AES backend (cryptography / PyCryptodome / pyaes / PyCrypto), auto-selected in `tinytuya/core/crypto_helper.py`. Do not add hard dependencies. Never import a crypto library outside `crypto_helper.py` — use `AESCipher`, and gate GCM-dependent features on `CRYPTOLIB_HAS_GCM`.

## Build, Test, Lint

```bash
pip install -e .                     # dev install
python -m tests                     # offline unit tests (tests.py) — must pass, no devices needed
python test.py <ID> <IP> <KEY> <VER> # live smoke test against a real device (optional)
pylint --recursive y -E tinytuya/    # errors-only lint, matches CI
```

CI (`.github/workflows/`) runs `tests.py` on Python 3.7–3.12, pylint (errors only), CodeQL, and `testcontrib.py` for Contrib modules. All must stay green.

- Add regression tests to `tests.py` (unittest + `MagicMock` sockets — see existing tests for the pattern of mocking `_get_socket`/`send`/`receive`). Tests must run offline.
- Contrib device classes get exercised by `testcontrib.py`.
- For protocol work, `tools/fake-v35-device.py` emulates a v3.5 device locally; `tools/broadcast-relay.py` helps with discovery testing.

## Code Conventions

- **Error handling**: runtime device/cloud failures return `error_json()` dicts (`{"Error", "Err", "Payload"}`) — codes and messages live in `tinytuya/core/error_helper.py` (900–914). Do not raise exceptions for network/device failures in library paths; reserve exceptions for programmer errors and `DecodeError` for framing. New error codes go in the table there *and* in the README error table.
- **Logging**: use the module `log = logging.getLogger(...)` objects; secrets (local keys, session keys, cloud apiSecret, tokens) must never appear in log output at any level, in `__repr__`, or in printed output. Guard expensive log formatting (e.g. hexlify) with `log.isEnabledFor(logging.DEBUG)`.
- **Style**: no type annotations are used in this codebase — match that. 4-space indents, descriptive lowercase function names, existing docstring style (signature summary at module/class top). Keep the comment density of surrounding code. Code must pass `pylint -E`.
- **Public API stability**: `tinytuya/__init__.py` wildcard-exports the core; a great deal of downstream code (Home Assistant integrations, forks, tutorials) depends on existing names, argument orders, and the error-dict shape. Never rename or reorder existing public parameters; add new parameters with defaults at the end. Deprecate softly (keep aliases) rather than removing.
- **Protocol changes**: anything touching `message_helper.py`, `header.py`, `crypto_helper.py`, or `_encode_message`/`_decode_payload`/session negotiation in `XenonDevice.py` must be reflected in PROTOCOL.md in the same PR.
- **Device quirks**: express per-version/per-dev_type command differences via the `payload_dict` template overlays in `XenonDevice.py`, not scattered `if version ==` branches.

## Adding a Contrib Device Module

New community device classes follow a fixed pattern (see existing modules in `tinytuya/Contrib/`):

1. `tinytuya/Contrib/<Name>Device.py` — a class subclassing `Device`, category helpers only (no protocol logic), with a module docstring listing author, product, and usage.
2. Add a section to `tinytuya/Contrib/README.md` (device, author link, usage snippet using `from tinytuya.Contrib import <Name>Device`).
3. Add an example under `examples/Contrib/`.
4. Add coverage in `testcontrib.py`.
5. Add a `RELEASE.md` bullet crediting the contributor and PR number.

## Documentation Map

When behavior changes, update the matching docs in the same change:

| Change | Update |
|---|---|
| Public API (methods, args, defaults) | `README.md` function lists + `tinytuya/__init__.py` docstring |
| Wire protocol / framing / crypto | `PROTOCOL.md` |
| Architecture / module boundaries | `DESIGN.md` |
| Any user-visible change | `RELEASE.md` (bullet with PR # and author credit) |
| New error code | `error_helper.py` + README error table |
| Contrib module | `Contrib/README.md` + `examples/Contrib/` |

Commit messages follow the loose `scope: summary` style visible in `git log` (e.g. `README: add auto_reconnect example`, `fix: call detect_bulb() before reading value_max`).

## Safety Rails

- **Never commit real credentials**: `devices.json`, `tinytuya.json`, `tuya-raw.json`, and `snapshot.json` contain local keys and/or cloud API secrets. Use obviously fake IDs/keys (`0123456789abcdef`, `abcdefghijklmnop123456`) in docs, examples, and tests.
- **Files containing secrets** written by the wizard/scanner should be created with restrictive permissions (`0o600`) — preserve/extend this, don't regress it.
- **Don't weaken crypto for convenience**: nonces/IVs must come from a proper source (`os.urandom`), never derived from time, constants, or log-level state. The static discovery key and ECB modes are Tuya protocol mandates — everything beyond that should follow modern practice.
- **Be conservative on the device wire path**: retries, timeouts, and heartbeats interact with flaky consumer firmware; aggressive polling can crash devices. Changes to retry/persistence behavior need testing against real hardware or `tools/fake-v35-device.py` and a note in the PR.

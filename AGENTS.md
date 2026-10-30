# AGENTS.md — Guide for Coding Agents and Contributors

TinyTuya is a Python library to control Tuya-based WiFi smart devices over the local network, plus a Tuya Cloud client, network scanner, setup wizard, and CLI. Read [DESIGN.md](DESIGN.md) for the architecture before changing core code, and [PROTOCOL.md](PROTOCOL.md) before touching anything on the wire path.

## Quick Facts

- **Language/support**: Python 3.10–3.15 (the CI matrix; `python_requires=">=3.10"` in `setup.py`). Code must run on 3.10, so no 3.11+ features (`except*`, `tomllib`, `typing.Self`, ...). Python 2 and pre-3.10 shims (`IS_PY2`, `from __future__`, `sys.hexversion`/`OrderedDict` fallbacks) are dead code — do not extend or copy them; removing them is welcome (keep `IS_PY2` as an alias, it is public).
- **Version source of truth**: `version_tuple` in `tinytuya/core/core.py`. Bump only as part of a release, together with a `RELEASE.md` entry.
- **Dependencies**: `requests`, `colorama`, and exactly one AES backend (cryptography / PyCryptodome / pyaes / PyCrypto), auto-selected in `tinytuya/core/crypto_helper.py`. Do not add hard dependencies. Never import a crypto library outside `crypto_helper.py` — use `AESCipher`, and gate GCM-dependent features on `CRYPTOLIB_HAS_GCM`.

## Build, Test, Lint

```bash
pip install -e . -r requirements-dev.txt  # dev install + pinned lint tooling
python -m tests                     # offline unit tests (tests.py) — must pass, no devices needed
python testcontrib.py               # Contrib import/init smoke test
python test.py <ID> <IP> <KEY> <VER> # live smoke test against a real device (optional)
pylint --recursive y -E tinytuya/    # errors-only lint, matches CI (use the pinned version)
```

CI lives in `.github/workflows/`; everything must stay green:

- `ci.yml` — **Pylint** (errors only, Python 3.12, pylint pinned in `requirements-dev.txt`); **Test** on Python 3.10–3.15 (`compileall`, `tests.py`, `test.py` smoke, `testcontrib.py`); **Crypto backend** runs `tests.py` once per AES backend (cryptography, pycryptodome, pycryptodomex, pyaes) with only that backend installed; **Coverage** reports line coverage of `tests.py` + `testcontrib.py` and fails below the `--fail-under` floor in `ci.yml` (raise the floor as coverage grows; never lower it to pass); **Build package** builds the sdist/wheel and runs `twine check`.
- `codeql-analysis.yml` — CodeQL security scanning (push, PR, weekly).
- `.github/dependabot.yml` proposes monthly bumps for Actions and the pylint pin. Bump the pin deliberately and fix any new findings in the same PR; never unpin.
- Adding or dropping a Python version means updating the `ci.yml` matrix, the support line above, and `python_requires` plus the version classifiers in `setup.py` together.

- Add regression tests to `tests.py` (unittest + `MagicMock` sockets — see existing tests for the pattern of mocking `_get_socket`/`send`/`receive`). For anything on the wire path (framing, crypto, session keys, retries, retcodes), drive the real `Device` API against the `FakeTuyaDevice` fixture in `tests.py` instead of mocking `_send_receive`; it speaks 3.1–3.5, and time is faked so retry loops never sleep. Tests must run offline. The only regression suites CI runs are `python -m tests` and `testcontrib.py` (plus a `test.py` usage-path smoke check) — tests in other files or runners (e.g. pytest suites) never run in CI.
- `TestApiContract` holds the code to API.md (every documented signature, the error-code and Contrib tables) and `TestAgentsRules` checks the mechanical rules in this file (no `print()` or logging setup in library code, crypto imports, logger names, no annotations, version/dependency sync). A known deviation is listed in `tests.py` as an `expectedFailure` for discussion: when you fix one, delete its entry (the run fails until you do), and never add an entry to get a change through.
- Test fixtures for `devices.json` rows must use the schema the wizard actually writes (`product_id`, not `productKey`; see `DEVICEFILE_SAVE_VALUES` in `core/const.py`). Hand-written fixtures with extra fields hide `KeyError`s on real user files.
- Lint and test a PR as merged onto current `master`, not just its branch — an old base can fail (or pass) for reasons unrelated to the change. Never get CI green with `--ignore`, blanket `disable`, or excluding files; a narrow `# pylint: disable-next=<msg>` for a verified false positive is fine.
- Contrib device classes get exercised by `testcontrib.py`.
- For protocol work, `tools/fake-v35-device.py` emulates a v3.5 device locally; `tools/broadcast-relay.py` helps with discovery testing.

## Code Conventions

- **Error handling**: runtime device/cloud failures return `error_json()` dicts (`{"Error", "Err", "Payload"}`) — codes and messages live in `tinytuya/core/error_helper.py` (900–914). Do not raise exceptions for network/device failures in library paths; reserve exceptions for programmer errors and `DecodeError` for framing. New error codes go in the table there *and* in the README error table.
- **Logging**: use the module `log = logging.getLogger(__name__)` objects; never rewrite logger names (users filter on them). Library code must not configure logging (handlers, formatters, `basicConfig`) — only the explicit `set_debug()` helper may. Per-device context goes in the message or a `LoggerAdapter`, not in per-instance logger names. No `print()` in library modules; only the CLI, wizard, and scanner user-facing output may print. Guard expensive log formatting (e.g. hexlify) with `log.isEnabledFor(logging.DEBUG)`.
- **Credentials are shown on purpose**: TinyTuya is a diagnostic and troubleshooting tool, so local keys, session keys, cloud apiSecret and tokens may appear in debug logs, `__repr__`, and CLI/scanner/wizard output. Do not mask, redact, or strip them. When asking users for logs in docs or issue replies, remind them to remove keys before posting publicly.
- **Style**: no type annotations are used in this codebase — match that. 4-space indents, descriptive lowercase function names, existing docstring style (signature summary at module/class top). Keep the comment density of surrounding code. Code must pass `pylint -E`.
- **Public API stability**: `tinytuya/__init__.py` wildcard-exports the core; a great deal of downstream code (Home Assistant integrations, forks, tutorials) depends on existing names, argument orders, and the error-dict shape. Never rename or reorder existing public parameters; add new parameters with defaults at the end. Deprecate softly (keep aliases) rather than removing.
- **Protocol changes**: anything touching `message_helper.py`, `header.py`, `crypto_helper.py`, or `_encode_message`/`_decode_payload`/session negotiation in `XenonDevice.py` must be reflected in PROTOCOL.md in the same PR.
- **Wildcard exports**: any new module pulled in by a `from .X import *` in `tinytuya/__init__.py` or `tinytuya/core/__init__.py` must define `__all__`, so it cannot shadow existing names (e.g. `log`).
- **Network defaults**: new behavior that sends extra traffic to devices (polling, probing, retries) is opt-in on library APIs (`deviceScan()`, `Device` methods); the CLI may opt in. Existing callers must not see new traffic or slower calls after upgrading.
- **Scanner**: new scanner features go in the `DeviceDetect` state-machine classes or small helpers, not the `scanner.devices()` main loop (see DESIGN.md). Do not re-indent large existing blocks; wrap them in a function instead so the diff stays reviewable.
- **One protocol implementation**: framing, crypto, session-key negotiation, and payload generation exist once (in `XenonDevice.py` and the `core/*_helper.py` modules). New I/O layers (e.g. any async API) must call into that shared logic and own only socket I/O — never copy it, or wire fixes have to land twice and drift. `Monitor._process_buffer()` is the one known exception (it duplicates `_receive()` framing; tracked as debt in DESIGN.md / #713) — shrink it, don't extend the pattern.
- **asyncio code** (when present): let `CancelledError` propagate; never block the event loop; isolate user-callback exceptions so one callback cannot kill the others.
- **Device quirks**: express per-version/per-dev_type command differences via the `payload_dict` template overlays in `XenonDevice.py`, not scattered `if version ==` branches.

## Pull Request Scope

- One concern per PR. Documentation PRs do not change behavior, move modules, rename constants, or bump versions — split those out.
- New public classes (e.g. a new device type) ship opt-in, with offline tests in `tests.py` and docs, and do not change default CLI or scanner output in the same PR.
- Stale branches that conflict with since-refactored modules (e.g. the old monolithic `core.py`) are ported as a fresh PR off `master`, crediting the original author, rather than resolving years-old conflicts.
- Version bumps and major-version (breaking) changes happen only in a release PR. Breaking changes need a migration note in RELEASE.md and README and must keep soft-deprecated aliases where possible.

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
| Any user-visible change | `RELEASE.md` (one- or two-sentence bullet with PR # and author credit, under the feature or bug-fix grouping it belongs to) |
| New error code | `error_helper.py` + README error table |
| Contrib module | `Contrib/README.md` + `examples/Contrib/` |

Commit messages follow the loose `scope: summary` style visible in `git log` (e.g. `README: add auto_reconnect example`, `fix: call detect_bulb() before reading value_max`).

## Safety Rails

- **Never commit real credentials**: `devices.json`, `tinytuya.json`, `tuya-raw.json`, and `snapshot.json` contain local keys and/or cloud API secrets. Use obviously fake IDs/keys (`0123456789abcdef`, `abcdefghijklmnop123456`) in docs, examples, and tests.
- **Credential files are plain text by design**: other tools and integrations read `devices.json`, `tinytuya.json`, `snapshot.json` and `tuya-raw.json` directly, so keep keys and secrets in the clear there. Do not encrypt, obfuscate, or change their format.
- **Don't weaken crypto for convenience**: nonces/IVs must come from a proper source (`os.urandom`), never derived from time or constants. The one deliberate exception: with DEBUG logging enabled, `AESCipher.get_encryption_iv()` uses a fixed v3.5 GCM IV (`b'0123456789ab'`) to aid packet analysis. Normal operation must stay random; `tests.py` checks both modes. The static discovery key and ECB modes are Tuya protocol mandates — everything beyond that should follow modern practice.
- **Be conservative on the device wire path**: retries, timeouts, and heartbeats interact with flaky consumer firmware; aggressive polling can crash devices. Changes to retry/persistence behavior need testing against real hardware or `tools/fake-v35-device.py` and a note in the PR.

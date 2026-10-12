# Changelog

All notable changes to `phocinae-cli` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] — 2026-10-12

### Security — four reproducible L0 bypasses are closed

Found by running the published 0.1.1 wheel rather than the source checkout, and
comparing it against `phocinae-guard`. The same gate gave opposite answers in the
two packages:

| command | phocinae-guard | phocinae-cli 0.1.1 |
|---|---|---|
| `ls\nrm -rf /` | deny | **allow** |
| `ls\trm -rf /` | deny | **allow** |
| `echo pwned>/etc/passwd` | deny | **allow** |
| `ls ; \rm -rf /` | deny | **allow** |

That is worse than a missing feature. A user who installs the CLI reasonably
believes they have the same gate as guard, and instead has a weaker one that
looks identical from the outside.

Root cause: the CLI carried **two hand-copied** L0 implementations —
`src/phocinae_cli/l0.py` and the single-file `phocinae.py` — both described in
their own comments as ported from phocinae-guard 0.1.0. When guard closed ten
bypasses in 0.1.3 with segment-aware matching, neither copy followed. Both
copies also normalised with `re.sub(r"\s+", " ")`, which folds a newline into a
space and destroys the command boundary the blacklist patterns anchor on, and
neither split the command into segments.

### Changed

- Both L0 implementations are now **generated from phocinae-guard** by
  `tools/`-style regeneration rather than hand-maintained: the function bodies
  are extracted verbatim from `guard.py` and the table is guard's built-in
  `DEFAULT_L0`. `load_table` / `l0_judge` / `_normalize` keep their existing
  names and 2-tuple contracts, so `gate.py`, `score_gate_cli.py` and
  `cmd_gate` are unchanged.
- `tests/test_l0_parity.py` compares **all three** implementations
  (guard, `phocinae_cli.l0`, `phocinae.py`) verdict-by-verdict over a 33-command
  corpus that includes every bypass sample guard has been fixed for. 66
  comparisons, 0 mismatches. It runs in CI, which checks out phocinae-guard
  beside the repository for exactly this purpose.
- `python -m pytest -q` is now allowed, matching guard 0.1.4: the allowlist had
  `python3 -m pytest` but Windows has no `python3`, so the most common way to run
  a test suite there was falling to the grey zone and failing closed.

### Migration

`pip install --upgrade phocinae-cli`. Anyone relying on the CLI's gate for
protection should upgrade; the previous version allowed four shell bypasses that
guard has denied since 0.1.3.

Verified: `tests/smoke.py` 51/51, `tests/test_l0_parity.py` 33/33 across three
implementations, and the wheel downloaded from PyPI after publishing re-tested for
all four bypasses.

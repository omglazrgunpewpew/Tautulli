# Vendored Security Checks

Date: 2026-10-26

> ⚠ Verify before relying on: urllib3 2.8.0 changes TLS handling for HTTPS forwarding proxies. Requests can read proxy settings from the environment, and no proxied request was tested. Verify this path if the installation uses an HTTPS forwarding proxy.

## Scope

Update the declared and bundled PyJWT, urllib3, and certifi packages to the versions selected for the October security maintenance. Tautulli.py inserts `lib/` at the start of `sys.path`, so the bundled files control runtime imports. Preserve application behavior and configuration.

## Requirements And Invariants

- Keep PyJWT claim and signature verification enabled according to existing callers.
- Preserve the repository's documented Python minimum of 3.10, raised by commit `4de6afe19` on 2026-03-27.
- Keep the existing dependency pins and bundled payloads aligned.
- Preserve package license material with the vendored source.
- Do not start the application server or make requests to Plex or other providers.

## Implementation

- requirements.txt pins PyJWT 2.15.0, urllib3 2.8.0, and certifi 2026.10.23.
- The vendored source came from the corresponding official PyPI wheels, installed with pip into an external staging directory, then copied into lib/.
- PyJWT 2.15.0 copies the caller's options mapping before applying defaults. Its wheel metadata requires Python 3.9 or newer. urllib3 2.8.0 requires Python 3.10 or newer, matching the repository's declared minimum.
- The upstream license files are included with the vendored package directories.
- `tests/test_vendored_security.py` covers the vendored import path and versions, PyJWT claim option reuse and signature rejection, chunked Deflate completion with trailing bytes, and rejection of oversized chunk-size lines. The workflow `.github/workflows/vendored-security.yml` runs those checks on the maintenance branch, pull requests, and manual dispatch with read-only repository permissions.

## Package Provenance

| Package | Wheel | SHA-256 |
| --- | --- | --- |
| PyJWT 2.15.0 | pyjwt-2.15.0-py3-none-any.whl | 7a3742debf6b879e912dbb9819ceec1594be812452b78c5f2e2dfc56564954f8 |
| urllib3 2.8.0 | urllib3-2.8.0-py3-none-any.whl | 0cf3cae568d36aa9576b28dfb35f11328f1cb974ca7647d9475ebb86c75ac6e3 |
| certifi 2026.10.23 | certifi-2026.10.23-py3-none-any.whl | e9b54de76e530bb6cf0ccd036787103acb58fd42ba930ea8bf948ddbaa2f61d1 |

Wheel release pages: [PyJWT](https://pypi.org/project/PyJWT/2.15.0/), [urllib3](https://pypi.org/project/urllib3/2.8.0/), [certifi](https://pypi.org/project/certifi/2026.10.23/).

## Validation

- The five focused security tests passed on Python 3.10.22 and Python 3.13.11. Both environments imported all three packages from this checkout's `lib/` directory.
- JWT round-trip passed. The wrong signing key was rejected. An expired token was rejected after reusing an options dictionary first passed to an unsigned decode, and the dictionary remained unchanged.
- The chunked Deflate trailing-bytes case completed within the test timeout on urllib3 2.8.0. The same payload stayed stuck beyond three seconds on urllib3 2.7.0. A chunk-size line above the limit was rejected.
- certifi's CA bundle path resolved to vendored `lib/certifi/cacert.pem`, which contains PEM certificates.
- `python Tautulli.py --help` completed successfully and did not start the server.

## Residual Compatibility Check

urllib3 2.8.0 corrects TLS handling for HTTPS forwarding proxies. Requests honors environment proxy settings by default. No outbound request was made, so a configured HTTPS proxy remains unverified. No Tautulli or provider configuration was changed.

## Handoff

Candidate review metadata, the target and merge-base SHAs, commit SHA, and clean-worktree result are stored outside this checkout alongside the maintenance worktree.

## Fork Branch Policy

The inherited nightly-only pull request routing rule applies to the canonical Tautulli repository. This personal fork permits maintenance pull requests to its default master branch. The branch check keeps the canonical repository condition, while the independent Python security matrix remains required for this fork.

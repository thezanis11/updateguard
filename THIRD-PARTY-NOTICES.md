# Third-party dependencies and data

UpdateGuard source is MIT licensed. Dependencies are installed separately from official PyPI distributions and retain their licenses. No dependency source or binary is vendored in this repository.

| Dependency | Purpose | Upstream license |
|---|---|---|
| [python-tuf](https://github.com/theupdateframework/python-tuf) | Metadata and client protocol | MIT OR Apache-2.0 |
| [securesystemslib](https://github.com/secure-systems-lab/securesystemslib) | Signing interfaces | MIT |
| [cryptography](https://github.com/pyca/cryptography) | Ed25519 backend | Apache-2.0 OR BSD-3-Clause |
| [urllib3](https://github.com/urllib3/urllib3) | HTTP transport | MIT |
| [cffi](https://github.com/python-cffi/cffi) | Native interface dependency | MIT-0 (locked 2.1.1 distribution metadata) |
| [pycparser](https://github.com/eliben/pycparser) | C parser dependency | BSD-3-Clause |

Consult the exact distribution metadata and license files for bundled native components. In particular cryptography wheels include native components with their own notices. `docs/DEPENDENCY_PROVENANCE.json` records official PyPI metadata, artifact URLs, sizes and SHA-256 values for the locked versions. These records are provenance, not a claim that all platform wheels were downloaded or executed.

All firmware artifacts, device states and adversarial responses used here are generated synthetic fixtures. No external dataset, real firmware image, production signing key or personal device identifier is distributed.

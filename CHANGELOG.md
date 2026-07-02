# Changelog

## [1.4.1](https://github.com/pksorensen/pks-agent-registry/compare/agent-registry-v1.4.0...agent-registry-v1.4.1) (2026-07-02)


### Bug Fixes

* **server:** advertise pull scope in the initial anonymous 401 challenge ([95fb12c](https://github.com/pksorensen/pks-agent-registry/commit/95fb12c34de55b5882c78c1299ba7f50e4fe3f43))

## [1.4.0](https://github.com/pksorensen/pks-agent-registry/compare/agent-registry-v1.3.1...agent-registry-v1.4.0) (2026-07-02)


### Features

* **registry:** GitHub OIDC federated auth — token service + trust bindings (ADR 0003) ([6bedf30](https://github.com/pksorensen/pks-agent-registry/commit/6bedf30bf8f7f1da4d65010819d8a5d220a41a57))
* **registry:** log auth failures and permission denials ([22ead8a](https://github.com/pksorensen/pks-agent-registry/commit/22ead8ae08f2c7f70edd20c7722598af4dc725e3))

## [1.3.1](https://github.com/pksorensen/pks-agent-registry/compare/agent-registry-v1.3.0...agent-registry-v1.3.1) (2026-06-24)


### Bug Fixes

* **registry:** anchor the /v2/ base route so unknown endpoints 404 instead of 200-empty ([453268c](https://github.com/pksorensen/pks-agent-registry/commit/453268c62dae87c6ecb59136bf22d8205d76eb48))

## [1.3.0](https://github.com/pksorensen/pks-agent-registry/compare/agent-registry-v1.2.1...agent-registry-v1.3.0) (2026-06-24)


### Features

* **cli:** distribute agent-registry CLI via agentics.dk install + ship tool docs ([198f442](https://github.com/pksorensen/pks-agent-registry/commit/198f4428fa519c23c0ea3567843cb9323971aab2))

## [1.2.1](https://github.com/pksorensen/pks-agent-registry/compare/agent-registry-v1.2.0...agent-registry-v1.2.1) (2026-06-24)


### Bug Fixes

* **registry:** implement OCI 1.1 referrers API so modern Docker can pull multi-arch images ([4b9c9bd](https://github.com/pksorensen/pks-agent-registry/commit/4b9c9bdde5a59540980acda4f311a06c990de15c))

## [1.2.0](https://github.com/pksorensen/pks-agent-registry/compare/agent-registry-v1.1.0...agent-registry-v1.2.0) (2026-06-21)


### Features

* **registry:** scope owner credentials with push/pull permissions ([e3ddca7](https://github.com/pksorensen/pks-agent-registry/commit/e3ddca74db620a7da83f13eeffd175bba3286cc4))

## [1.1.0](https://github.com/pksorensen/pks-agent-registry/compare/agent-registry-v1.0.1...agent-registry-v1.1.0) (2026-06-14)


### Features

* REGISTRY_TRUSTED_PROXY_CIDRS — anonymous reads from trusted proxy ([c384457](https://github.com/pksorensen/pks-agent-registry/commit/c38445785c64243e05ddcfbd863a6b261139b8ea))


### Bug Fixes

* **security:** trusted-proxy bypass requires private XFF tail, not just proxy TCP source ([c1ade7e](https://github.com/pksorensen/pks-agent-registry/commit/c1ade7e8e3ec8e0ff6164218813f2246ac285b44))

## [1.0.1](https://github.com/pksorensen/pks-agent-registry/compare/agent-registry-v1.0.0...agent-registry-v1.0.1) (2026-05-25)


### Bug Fixes

* add Dockerfile healthcheck and publish release image to both registries ([59a6dd2](https://github.com/pksorensen/pks-agent-registry/commit/59a6dd2e423800e25d7bfdb41e42799ed1266629))

## 1.0.0 (2026-05-25)


### Features

* initial OCI v0 with admin CLI and mgmt API ([7985fb1](https://github.com/pksorensen/pks-agent-registry/commit/7985fb188ef110c2293d79b8c06e003dd33ee82e))
* remote admin mode for the CLI ([472a5d8](https://github.com/pksorensen/pks-agent-registry/commit/472a5d8cfe5d44618c155f0f95595652e9b61d3f))

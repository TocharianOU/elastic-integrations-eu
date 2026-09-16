# Elastic Integrations — EU

Elastic integration packages for European vendors that the official catalogue
does not cover.

This repository is the structural counterpart of
[`elastic/integrations`](https://github.com/elastic/integrations): the same
layout, the same package format, the same tooling. A package here can be copied
into that repository unchanged. It carries only what Elastic does not ship.

Maintained by [**TocharianOU**](https://tocharian.eu). Apache-2.0.

[![CI](https://github.com/TocharianOU/elastic-integrations-eu/actions/workflows/ci.yml/badge.svg)](https://github.com/TocharianOU/elastic-integrations-eu/actions/workflows/ci.yml)

## Why this exists

Elastic ships around 600 integrations, and few of them cover European products.
Vulnerability management upstream is Tenable, Qualys and Rapid7, with no package
for Greenbone. Proxmox VE, Nextcloud, Checkmk, Zabbix and the European clouds
have none either.

These packages cover part of that.

Every package here is built against the running product, not against sample
files: deploy it, drive real traffic through it, capture what it actually emits,
and derive the pipeline from that capture. The raw captures are kept in
[`_fixtures/`](_fixtures) so the mapping can be checked against the evidence it
came from, and the same captures serve as the pipeline test fixtures.

[`docs/roadmap.md`](docs/roadmap.md) lists what is and is not covered upstream.

## Packages

| Package | Vendor | Country | Category | Version | Verified against |
|---|---|---|---|---|---|
| [`crowdsec`](packages/crowdsec) | CrowdSec | FR | Intrusion prevention | 0.1.0 | CrowdSec 1.8.1 |
| [`opnsense`](packages/opnsense) | OPNsense | NL | Firewall | 0.1.0 | OPNsense 26.7 |

Other candidates are listed in [`docs/roadmap.md`](docs/roadmap.md).

## Installing

Packages reach Fleet through an
[Elastic Package Registry](https://github.com/elastic/package-registry) running in
**proxy mode**. The official catalogue passes through untouched and these packages
appear alongside it, so nothing has to be mirrored:

```yaml
# docker compose
services:
  registry:
    image: docker.elastic.co/package-registry/package-registry:main
    environment:
      EPR_FEATURE_PROXY_MODE: "true"
      EPR_PROXY_TO: "https://epr.elastic.co"
      EPR_ADDRESS: "0.0.0.0:8080"
    volumes:
      - ./packages:/packages/local        # built .zip files go here
      - ./config.yml:/package-registry/config.yml
```

```yaml
# config.yml
package_paths:
  - /packages/local
```

Then point Kibana at it:

```yaml
xpack.fleet.registryUrl: "https://your-registry.example.eu"
```

Built packages are attached to
[releases](https://github.com/TocharianOU/elastic-integrations-eu/releases), each
with its SHA-256, so the artifact your registry serves can be checked against the
one published here.

To install a single package directly instead:

```bash
curl -u "$USER:$PASS" -X POST \
  "$KIBANA/api/fleet/epm/packages/crowdsec/0.1.0" \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" \
  -d '{"force":true}'
```

## Building

Requires [`elastic-package`](https://github.com/elastic/elastic-package) and a
running stack. `elastic-package` resolves the repository root from git, so build
from a clone rather than a copied directory.

```bash
cd packages/crowdsec
elastic-package test pipeline    # runs the pipeline against the captured fixtures
elastic-package check            # lint + build; must pass before any contribution
elastic-package build            # produces build/packages/<name>-<version>.zip
```

## Releases and CI

Every push and pull request runs `elastic-package check` on each package, and the
pipeline tests against a real Elasticsearch, so a package that does not lint,
build or parse its own captured fixtures never reaches `main`.

A release is cut by tagging `<package>-v<version>`, for example `crowdsec-v0.1.0`.
The workflow refuses to publish if the tag's version does not match the package
manifest, so a release can never point at a differently versioned artifact.

## Layout

```
packages/<name>/     the integration package — the only part that is a deliverable
dashboards/          dashboard generators, one script per package
_fixtures/<name>/    raw payloads captured from the live product
tools/               helper scripts for replaying captures into a cluster
docs/roadmap.md      upstream coverage gaps
```

Everything outside `packages/` is method, not product. It is deliberately kept
out of the package directory so that a package stays a clean drop-in: the whole
directory can be copied into `elastic/integrations` with nothing to strip.

Dashboards are **generated from a script** rather than hand-exported from Kibana.
Kibana runs a long chain of saved-object migrations on install, and hand-edited
objects drift and break in ways that only surface after the package is installed.
Generating them keeps every package on the same visual language and makes a
change reviewable as a diff.

## Conventions

| Field | Value |
|---|---|
| `format_version` | `3.4.2` |
| `owner.github` | `elastic/security-service-integrations` |
| `owner.type` | `community` |
| `source.license` | `Apache-2.0` |
| `conditions.kibana.version` | `^8.19.0 \|\| ^9.1.0` |
| `conditions.elastic.subscription` | `basic` |
| UI language | English |

`owner.github` must name a team that `.github/CODEOWNERS` lists for the package
in `elastic/integrations`; the repository's codeowners check fails the build
otherwise. `owner.type` is `community`: these packages are built and maintained by
non-Elastic contributors, and upstream packages such as `pps` and `bbot` pair
`community` with an Elastic team the same way.

Every package carries its own `LICENSE.txt` declaring Apache-2.0, which
`source.license` permits alongside `Elastic-2.0`. Of the 93 upstream packages that
carry their own `LICENSE.txt`, 87 are Elastic License 2.0 and none are Apache-2.0.

## Contributing upstream

Copy `packages/<name>/` into a fork of `elastic/integrations`, add the package to
`.github/CODEOWNERS`, and open a pull request. Before opening it:

- run `/review-integration` from
  [`elastic/integration-skills`](https://github.com/elastic/integration-skills) —
  the same rules drive the automated reviewer on the pull request;
- run `elastic-package format`, `check`, `test pipeline` and `test script`.
  `check` does not catch formatting.

On a pull request from an external contributor, Buildkite and the GitHub Actions
checks start only once an Elastic maintainer triggers them.

## Support

Open an [issue](https://github.com/TocharianOU/elastic-integrations-eu/issues) for
bugs and questions. Include the product version and, where you can, a captured
payload — every package here was built from real captures, and that is what makes
a fix possible.

For anything else: [tocharian.eu](https://tocharian.eu) · info@tocharian.eu

## Licence

Apache License 2.0. See [LICENSE](LICENSE).

Product names and logos are trademarks of their respective owners. They are used
here only to identify the product each package collects data from.

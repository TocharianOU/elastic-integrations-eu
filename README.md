# Elastic Integrations — EU

Elastic integration packages for European vendors that the official catalogue
does not cover.

This repository is the structural counterpart of
[`elastic/integrations`](https://github.com/elastic/integrations): the same
layout, the same package format, the same tooling. A package here can be copied
into that repository unchanged. It carries only what Elastic does not ship.

Maintained by [**TocharianOU**](https://tocharian.eu). Apache-2.0.

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
| `format_version` | `3.3.2` |
| `owner.github` | `TocharianOU` |
| `owner.type` | `community` |
| `source.license` | `Apache-2.0` |
| `conditions.kibana.version` | `^8.18.0 \|\| ^9.0.0` |
| `conditions.elastic.subscription` | `basic` |
| UI language | English |

`owner.type` is `community`, which is the accurate value: these packages are
built and maintained by non-Elastic contributors. It becomes `partner` only if
and when the product vendor co-maintains one.

Every package carries its own `LICENSE.txt` declaring Apache-2.0. In
`elastic/integrations`, whose root licence is the Elastic License 2.0, a
`LICENSE.txt` in a directory subtree declares a different licence for that
subtree — the mechanism 92 upstream packages already use.

## Contributing upstream

A package here is ready to be proposed to `elastic/integrations`: copy
`packages/<name>/` in, and `elastic-package check` must pass before the pull
request. Note that upstream every package is code-owned by an Elastic team in
`.github/CODEOWNERS`, including packages whose `owner.type` is `community` — so
an Elastic team has to agree to take on the review and maintenance. That
agreement, not the code, is the real gate.

Until then these packages are distributed from here and from the registry above,
which nobody's approval is required for.

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

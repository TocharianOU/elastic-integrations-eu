# Coverage gaps

Which European products the official Elastic catalogue does not cover, and which
of them are candidates for a package here.

Baseline checked **2026-09-06** against `https://epr.elastic.co/search` — **497
packages** upstream at that point. Everything listed as covered was confirmed
present; everything in the gap table was confirmed absent. Re-check before
relying on it:

```bash
curl -s "https://epr.elastic.co/search?all=true&experimental=true" \
  | python3 -c "import json,sys;print('\n'.join(sorted({p['name'] for p in json.load(sys.stdin)})))"
```

## Already covered upstream

European or EU-relevant vendors that already have an official package, and so
are not candidates:

`stormshield` (FR) · `sophos`, `sophos_central` (UK) · `eset_protect`, `ti_eset`
(SK) · `bitdefender` (RO) · `withsecure_elements` (FI) · `keycloak` ·
`authentik` (DE) · `pfsense` · `traefik` · `haproxy` · `modsecurity` · `nginx` ·
`vsphere` · `gitlab` · `mattermost` · `teleport` · `ceph` · `nagios_xi`

`modsecurity` covers the ModSecurity/Coraza audit-log format generically, which
overlaps most of what a **BunkerWeb** (FR) package would add.

## Gap table

| Product | Country | Category | Upstream | Test deployment | Effort |
|---|---|---|---|---|---|
| **CrowdSec** | FR | Intrusion prevention | none | Docker | Low |
| **OPNsense** | NL | Firewall / UTM | only `pfsense` | VM, free | done |
| **Greenbone / OpenVAS** | DE | Vulnerability management | none | Docker, free CE | Medium |
| Proxmox VE | AT | Virtualization | only `vsphere` | Bare metal / nested | Med-High |
| Nextcloud | DE | Collaboration / audit | none | Docker | Medium |
| Checkmk | DE | Monitoring | none | Docker (Raw Edition) | Medium |
| Zabbix | LV | Monitoring | none | Docker | Medium |
| Icinga | DE | Monitoring | none | Docker | Medium |
| OVHcloud | FR | Cloud audit | none | Account required | Medium |
| Scaleway | FR | Cloud audit | none | Account required | Medium |
| Hetzner Cloud | DE | Cloud audit | none | Account required | Medium |
| IONOS | DE | Cloud audit | none | Account required | Medium |
| Matrix / Synapse | UK | Messaging | none | Docker | Medium |
| Wallix Bastion | FR | PAM | none | not obtainable | High |
| Gatewatcher | FR | NDR | none | not obtainable | High |
| Tehtris | FR | XDR | none | not obtainable | High |
| SAP | DE | ERP | none | not obtainable | High |

Rows marked *not obtainable* are blocked on access to a test system rather than
on engineering. Packages here are built against a running product, so without one
there is nothing to build from.

## Notes on the first three

### CrowdSec (France)

Done — see [`packages/crowdsec`](../packages/crowdsec).

Ingestion paths found on the live product:

- the `notification-http` plugin POSTs a JSON array of alerts to a URL, which the
  Elastic Agent `http_endpoint` input splits into one event per element. This is
  the path the package uses.
- the Local API `/v1/decisions/stream` returns a thinner shape than the
  notification payload, so it is not interchangeable with the above. Left out
  until it can be tested against a real bouncer key.

### OPNsense (Netherlands)

Done — see [`packages/opnsense`](../packages/opnsense).

The filterlog body is CSV whose column layout changes with the IP version and
then with the protocol: IPv6 reverses the two protocol columns relative to IPv4,
TCP carries a long tail of flags and sequence numbers, UDP stops after the ports,
and ICMP switches to `key=value`. The pipeline parses this positionally in one
script rather than as a stack of grok alternatives.

### Greenbone / OpenVAS (Germany)

Findings come over GMP (XML over TLS) and there is no Agent input for GMP, so it
needs a `cel` input against the report API or a small exporter. Findings map to
ECS `vulnerability.*`.

## Package conventions

| Field | Value |
|---|---|
| `format_version` | `3.3.2` |
| `owner.github` | `TocharianOU` |
| `owner.type` | `community` |
| `source.license` | `Apache-2.0` |
| `conditions.kibana.version` | `^8.18.0 \|\| ^9.0.0` |
| `conditions.elastic.subscription` | `basic` |
| UI language | English |

`source.license` is constrained by package-spec to exactly `Apache-2.0` or
`Elastic-2.0`.

Dashboards are generated from one script per package rather than hand-exported,
so saved objects do not drift and a change is reviewable as a diff.

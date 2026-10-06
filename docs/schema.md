# Rule pack schema (version 1)

`tools/packbuild build` combines the source files into one JSON document, `dist/rules-pack.json`. The application validates every pack when it loads it, and rejects packs with an unknown schema, invalid dates, broken references, or missing thresholds.

Dates are `YYYY-MM-DD`.

## manifest

| Field | Required | Notes |
|---|---|---|
| `version` | yes | `R<yyyy>.<mm>.<dd>.<n>`; releases are compared in this order |
| `schema` | yes | `1` |
| `min_app` | no | Lowest application version (`YY.M.NNN`) that may use the pack |
| `published` | yes | Release date |
| `description` | no | One line, shown to administrators |

## vsphere_lifecycle[]

| Field | Notes |
|---|---|
| `version` | ESXi / vCenter `major.minor`, for example `8.0` |
| `end_of_general_support` | Hosts and vCenters after this date are flagged as end of support. Within 13 months of it they're flagged as approaching. |
| `source` | Optional reference URL |

## guest_os_lifecycle

| Field | Notes |
|---|---|
| `exclude[]` | Lowercase substrings that are never matched, for example `ltsc` |
| `entries[].label` | Name shown in findings |
| `entries[].pattern` | Go regular expression matched against the lowercased guest OS name; first match wins |
| `entries[].end_of_support` | Vendor end of support (paid extended programs aren't modeled) |
| `entries[].source` | Optional |

## cpu_generations[]

`code`, `name`, `vendor`, and `launch` (year). The application maps CPU model strings to these codes. You can rename a generation or correct its launch year here, but adding a new code needs an application update that recognizes it.

Current codes: `westmere`, `sandy`, `ivy`, `haswell`, `broadwell`, `skylake`, `cascade`, `cooper`, `icelake`, `sapphire`, `emerald`, `xeon6`, `naples`, `rome`, `milan`, `genoa`, `turin`.

## cpu_support

| Field | Rule |
|---|---|
| `unsupported_esxi8[]` | Generations that can't run ESXi 8.0 (`cpu-esxi8`) |
| `deprecated[]` | Generations on Broadcom's deprecation list (`cpu-deprecated`) |

## firmware_advisories[]

| Field | Notes |
|---|---|
| `id` | Unique, stable identifier |
| `name` | Shown in findings |
| `cves[]` | CVE IDs |
| `note` | Optional text after the CVE list, for example `and related` |
| `families[]` | CPU generation codes; omit for UEFI flaws that apply to any x86 firmware |
| `disclosed` | Public disclosure date. A BIOS released before it is flagged. |
| `url` | Optional advisory link |

## hardware_lifecycle[]

`vendor`, `model` (case-insensitive substring of the RVTools model), `end_of_sale`, `end_of_support`, and `source`. Entries an administrator makes in the application take precedence.

## thresholds

All of these are required:

| Key | Meaning |
|---|---|
| `vcpu_per_core_warn` / `vcpu_per_core_high` | vCPU : physical core ratio for Medium / High CPU overcommit |
| `mem_alloc_warn_pct` | Memory allocated to powered-on VMs as % of host memory |
| `host_cpu_hot_pct` / `host_mem_hot_pct` | Host utilization at collection time |
| `ds_warn_pct` / `ds_crit_pct` | Datastore used % |
| `ds_overprov_pct` | Datastore provisioned % of capacity |
| `snap_age_warn_days` / `snap_age_high_days` | Snapshot age |
| `snap_size_high_gib` | Snapshot size |
| `min_hw_version` | Oldest acceptable VM hardware version (vmx-NN) |
| `guest_free_warn_pct` | Guest file system free space |
| `rightsize_active_pct` / `rightsize_min_mem_gib` | Memory right-sizing candidates |

## rules

Keyed by rule ID. Every rule the application can report is listed with its `name` and `category`; the application's tests fail if one is missing. Optional overrides:

| Field | Values |
|---|---|
| `enabled` | `false` stops reporting the rule |
| `severity` | `Info`, `Low`, `Medium`, `High`, `Critical` |
| `horizon` | `immediate`, `near-term`, `strategic` (roadmap placement) |
| `title`, `impact`, `recommendation` | Replace the application's wording |

The observation text includes counts and object names, so it stays in the application.

## changelog

`RULES-CHANGELOG.md` is embedded in the pack and shown on the application's What's new page.

## Signature

`rules-pack.json.sig` contains `ed25519:<key id>:<base64 signature>`. The signature covers the exact bytes of `rules-pack.json`.

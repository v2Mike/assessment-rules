# Assessment rules

Rule packs for the Greyson Assessments application: the reference data and rule settings it uses to evaluate VMware vSphere environments from RVTools exports.

A rule pack holds data, never code:

- vSphere (ESXi and vCenter) and guest operating system end-of-support dates
- CPU generations and their vSphere support status
- CPU and UEFI firmware vulnerabilities (CVEs) fixed by BIOS updates
- server hardware end-of-sale and end-of-support dates
- analysis thresholds, such as the vCPU-to-core ratio and datastore fill levels
- the rule catalog, with optional per-rule overrides: enable or disable a rule, change its severity or roadmap horizon, or replace its title, impact, or recommendation text

The application ships with a built-in pack and can install newer signed packs from this repository's releases without an application update. Each assessment records the pack it was analyzed with, so a delivered report can be reproduced.

> This repository is public. Contribute only public reference information: vendor lifecycle dates, published advisories, and general best practice. Never add customer names, hostnames, exports, or anything from an engagement.

## Layout

| File | Contents |
|---|---|
| `manifest.json` | Pack version, schema, minimum app version, publish date |
| `data/vsphere-lifecycle.json` | ESXi / vCenter end of general support, by major.minor |
| `data/guest-os-lifecycle.json` | Guest OS patterns and end-of-support dates (first match wins) |
| `data/cpu-generations.json` | CPU generation codes, names, and launch years |
| `data/cpu-support.json` | Generations unsupported on ESXi 8, and deprecated generations |
| `data/firmware-advisories.json` | CPU / UEFI firmware vulnerabilities and their disclosure dates |
| `data/hardware-lifecycle.json` | Server model end-of-sale and end-of-support dates |
| `thresholds.json` | Numeric limits the rules compare against |
| `rules.json` | Rule catalog and per-rule overrides |
| `RULES-CHANGELOG.md` | Release notes, shown in the app |
| `keys/release-key.pub` | Public key that verifies release signatures |
| `tools/packbuild` | Builds, validates, signs, verifies, and diffs packs |

The field reference is in [docs/schema.md](docs/schema.md).

## Common changes

**Add a firmware vulnerability.** Append to `data/firmware-advisories.json`:

```json
{
  "id": "example-2026",
  "name": "Example side-channel",
  "cves": ["CVE-2026-12345"],
  "families": ["sapphire", "emerald"],
  "disclosed": "2026-09-09",
  "url": "https://example.com/advisory"
}
```

`families` lists CPU generation codes from `data/cpu-generations.json`; leave it out for UEFI firmware flaws that apply to any x86 server. A host is flagged when its BIOS release date is earlier than `disclosed`, because that BIOS can't contain the fix.

**Update a lifecycle date.** Edit the date in `data/vsphere-lifecycle.json` or `data/guest-os-lifecycle.json`. Guest OS patterns are regular expressions matched against the lowercased OS name, and the first match wins, so put more specific patterns first.

**Change a threshold.** Edit `thresholds.json`. For example, `"ds_crit_pct": 90` flags datastores at 90% or more as critical.

**Tune a rule.** Add fields to the rule in `rules.json`:

```json
"vm-cbt": {
  "name": "VMs without Changed Block Tracking",
  "category": "Operational Hygiene",
  "enabled": true,
  "severity": "Medium",
  "recommendation": "Enable CBT so image-level backups (Rubrik, Cohesity, Veeam) can run incremental jobs."
}
```

Set `"enabled": false` to stop reporting a rule. Fields you leave out keep the application's default.

## Releasing

1. Make your changes on a branch. The **Validate** workflow builds the pack and posts a summary of what changed against the latest release.
2. Bump `version` in `manifest.json`, using `R<yyyy>.<mm>.<dd>.<n>` (for example `R2026.10.20.1`), and set `published` to the same date.
3. Add a `## <version> - <date>` section to `RULES-CHANGELOG.md`.
4. Merge to `main`. The **Release** workflow builds, validates, and signs the pack, then publishes a GitHub release with `rules-pack.json` and `rules-pack.json.sig`.

Application administrators then see the update under **Settings → Assessment rules**. There they can preview its effect on existing assessments and activate it.

Set `min_app` in the manifest when a pack uses a field that older application versions don't understand.

## Building locally

```bash
go run ./tools/packbuild build                       # dist/rules-pack.json (validates)
go run ./tools/packbuild diff -old old.json -new dist/rules-pack.json
RULES_SIGNING_KEY=... go run ./tools/packbuild sign  # maintainers only
go run ./tools/packbuild verify -pub "$(grep -v '^#' keys/release-key.pub)"
```

## Signing

Releases are signed with an ed25519 key. The private key is stored as the `RULES_SIGNING_KEY` Actions secret, and the application embeds the public key, so a pack that was modified after release, or signed with another key, is rejected. To rotate the key, add the new public key to the application first, release an app update, and then switch the secret.

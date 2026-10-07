# Rules changelog

Changes to assessment rule packs. Each pack version is R<year>.<month>.<day>.<n>.
The app shows this file on its What's new page, next to the app's own release notes.

## R2026.10.06.2 - 2026-10-06
### New
- **Network adapters that won't reconnect after a power cycle** (`vm-nic-start-disconnected`, Medium, Availability & Resiliency). Flags powered-on VMs whose network adapter is connected now but has "Connect At Power On" turned off, so the VM loses its network after the next power-on or HA restart. Requires application 26.10.004 or later, which reads the RVTools "Starts Connected" column. Older applications ignore this rule.

## R2026.10.06.1 - 2026-10-06
### New
- First published rule pack. It holds the reference data and rule settings that were compiled into the app through 26.9.009, with identical results: vSphere and guest OS lifecycle dates, CPU generations and vSphere CPU support, 10 firmware advisories, analysis thresholds, and the catalog of 87 rules.

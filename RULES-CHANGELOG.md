# Rules changelog

Changes to assessment rule packs. Each pack version is R<year>.<month>.<day>.<n>.
The app shows this file on its What's new page, next to the app's own release notes.

## R2026.11.12.1 - 2026-11-12
### New
- **ESXi hosts missing critical security patches** (`esxi-patch`, Critical, Security & Configuration). Compares each host's ESXi build with the first fixed build in these VMware advisories:
  - VMSA-2025-0004: CVE-2025-22224, CVE-2025-22225, CVE-2025-22226. Exploited in the wild and used in ransomware attacks.
  - VMSA-2025-0013: CVE-2025-41236, CVE-2025-41237, CVE-2025-41238. VM escape, CVSS 9.3.
  - VMSA-2026-0006: CVE-2026-47876 (VMXNET3 VM escape, CVSS 9.3), CVE-2026-41703, and CVE-2026-41709. Fixed in ESXi 8.0 U3k, ESXi 8.0 U2f, ESX 9.0.2.0100, and ESX 9.1.0.0200. ESXi 7.0 has no public fix.
- **vCenter Server missing critical security patches** (`vcenter-patch`, Critical, Security & Configuration). Compares each vCenter build with:
  - VMSA-2024-0019: CVE-2024-38812 and CVE-2024-38813. Exploited in the wild.
  - VMSA-2026-0006: CVE-2026-59309, an authentication bypass, and CVE-2026-59310, a Syslog directory traversal, both CVSS 9.8. Fixed in vCenter 8.0 U3k, 8.0 U2f, 9.0.2.0100, and 9.1.0.0300. vCenter 7.0 has no public fix.
- Both checks need application 26.11.001 or later. Older applications ignore them.
- **Firmware advisories:** a host is flagged when its BIOS predates disclosure.
  - EntrySign, AMD microcode signature verification (CVE-2024-56161, CVE-2024-36347): EPYC Naples through Turin.
  - Indirect Target Selection (CVE-2024-28956): Xeon Cascade Lake, Cooper Lake, and Ice Lake.
  - Transient Scheduler Attacks (CVE-2024-36350, CVE-2024-36357): EPYC Milan and Genoa.
  - Intel 2026.3 IPU, INTEL-SA-01442 (CVE-2026-20713, CVE-2026-20901): 4th and 5th Gen Xeon Scalable and Xeon 6.
  - Intel 2026.3 IPU, INTEL-SA-01443 (CVE-2026-20707): 3rd Gen Xeon Scalable.
- **Guest OS lifecycle:** adds Windows Server 2022 and 2025, RHEL 8 and 9, Oracle Linux 8, Ubuntu 22.04 and 24.04, SLES 15, and Debian 11 and 12. Debian 11 LTS ended August 31, 2026, so Debian 11 VMs are now reported as end of life. Ubuntu 22.04 standard support ends May 2027, so those VMs are reported as approaching end of support.

## R2026.10.06.2 - 2026-10-06
### New
- **Network adapters that won't reconnect after a power cycle** (`vm-nic-start-disconnected`, Medium, Availability & Resiliency). Flags powered-on VMs whose network adapter is connected now but has "Connect At Power On" turned off, so the VM loses its network after the next power-on or HA restart. Requires application 26.10.004 or later, which reads the RVTools "Starts Connected" column. Older applications ignore this rule.

## R2026.10.06.1 - 2026-10-06
### New
- First published rule pack. It holds the reference data and rule settings that were compiled into the app through 26.9.009, with identical results: vSphere and guest OS lifecycle dates, CPU generations and vSphere CPU support, 10 firmware advisories, analysis thresholds, and the catalog of 87 rules.

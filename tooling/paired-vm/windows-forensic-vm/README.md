# Windows 11 25H2 forensic repair VM

This is a narrow Windows-native filesystem cross-check, not an unofficial
forensic distribution and not a replacement for the normal read-only
examination. It boots unchanged official Microsoft Windows 11 Enterprise
Evaluation media in a network-isolated QEMU/KVM VM and uses the Windows Setup
WinPE environment to run a logged `chkdsk` workflow.

The supported base is the English (United States), x64 Windows 11 Enterprise
Evaluation 25H2 ISO. Its required Microsoft-published SHA-256 is:

```text
A61ADEAB895EF5A4DB436E0A7011C92A2FF17BB0357F58B13BBC4062E535E7B9
```

Primary references:

- [Windows 11 Enterprise Evaluation](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise)
- [Microsoft evaluation ISO hash list](https://go.microsoft.com/fwlink/?linkid=2334901)
- [Windows Setup Automation Overview](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-automation-overview?view=windows-11)
- [`Microsoft-Windows-Setup` `RunSynchronous`](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-setup-runsynchronous)
- [`chkdsk` command reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/chkdsk)

## Why the official ISO is not repacked

The 25H2 evaluation download presents only a small ISO9660 compatibility stub
to common Linux ISO tools; the installer tree is UDF. Treating that stub as the
complete image hides `sources/boot.wim`, and reconstructing the ISO from that
view would not preserve Microsoft's BIOS/UEFI boot layout.

This workflow therefore leaves the official ISO byte-for-byte unchanged.
Automation is carried on a separate FAT image containing `Autounattend.xml`, a
marker, and `forensic-repair/run.cmd`. Microsoft documents that Windows Setup
searches the root of removable read-only media for `Autounattend.xml`, and that
`Microsoft-Windows-Setup/RunSynchronous` runs commands in the `windowsPE`
configuration pass. QEMU exposes the auxiliary image as a read-only removable
USB disk. The answer file has no disk configuration, image installation,
product key, or installation target settings; its only action finds the marker
and launches the offline script. If the script cannot prove the intended target
volume, it records failure and shuts the VM down.

## Safety model

- The official ISO is checked against the exact Microsoft hash, bind-mounted
  read-only, and attached to QEMU with `readonly=on`.
- The auxiliary FAT image is separately hashed, bound to a provenance record,
  bind-mounted read-only, and attached with `readonly=on`.
- `prepare-derivative` streams a separately named copy, refuses source/output
  aliasing, hard links, and symlinks, checks the supplied source SHA-256, and
  writes a derivative descriptor. An interrupted copy remains `.partial`.
- The original or source working image is never passed to QEMU.
- Scan mode bind-mounts the derivative read-only and also sets QEMU's drive
  `readonly=on`. The derivative is exposed as removable USB mass storage
  because QEMU's IDE hard-disk frontend requests write permission even from a
  read-only block node; the separate container bind mount remains the second
  read-only guard. Parameter-free `chkdsk` reports status without fixing it.
- Repair mode is refused unless a completed scan run is supplied, the prior
  scan's before/after hashes equal the current derivative hash, it has no changed
  extents, and `--allow-derivative-write` is explicit.
- Every repair run scans first, then runs `chkdsk /offlinescanandfix` only on the
  derivative. The guest identifies the volume by its exact Windows filesystem
  serial and refuses zero or multiple matches.
- Every container has `--network none`, QEMU has `-nic none`, Docker image pulls
  are disabled, the container root is read-only, and Linux capabilities are
  dropped.
- Each run receives a fresh FAT results disk and retains the QEMU log, guest
  outputs, before/after whole-file SHA-256 values, 1 MiB block maps, and
  coalesced changed-block extents.

Treat the source passed to `prepare-derivative` as a verified working image or
an already isolated partition derivative, never the only original evidence
copy. The source path is recorded only in controlled case output.

## Build the local tool image

The Ubuntu base digest is pinned. Ubuntu package repository state is not, so
record the resolved Docker image ID in the case and rebuild deliberately. Run
commands require the image to exist locally and use `--pull never`.

```bash
docker build \
  --tag forensic-copilot/windows-forensic-vm:win11-25h2 \
  tooling/paired-vm/windows-forensic-vm
docker image inspect forensic-copilot/windows-forensic-vm:win11-25h2
```

## Obtain and verify official media

`download-media.sh` uses Microsoft's HTTPS CDN, leaves a failed transfer as
`.partial`, and promotes it only after the exact published hash matches. Check
the Evaluation Center and hash list again in a future case because the current
release and direct download URL can change.

```bash
sh tooling/paired-vm/windows-forensic-vm/download-media.sh \
  /cases/CASE-001/tooling/windows-11-enterprise-25h2.iso

python tooling/paired-vm/windows-forensic-vm/forensic_vm.py verify-media \
  --iso /cases/CASE-001/tooling/windows-11-enterprise-25h2.iso
```

## Build the read-only auxiliary media

This command does not read or rewrite the Microsoft ISO. It creates a FAT image
with a fixed label and volume ID, normalizes the batch file to CRLF, hashes the
image and payload sources, and writes `auxiliary-media.json`.

```bash
python tooling/paired-vm/windows-forensic-vm/forensic_vm.py build-auxiliary-media \
  --output-dir /cases/CASE-001/tooling/windows-forensic-auxiliary
```

Before case use, inspect the auxiliary image or mount a copy read-only and
confirm that it contains only:

```text
Autounattend.xml
FORENSIC_AUX.TAG
forensic-repair/run.cmd
```

## Prepare the derivative

```bash
python tooling/paired-vm/windows-forensic-vm/forensic_vm.py prepare-derivative \
  --source /cases/CASE-001/working/source-a.raw \
  --source-sha256 VERIFIED_WORKING_IMAGE_SHA256 \
  --output /cases/CASE-001/repair/source-a.windows-derivative.raw
```

For a full disk, pass the physical partition number to `run`. For a standalone
filesystem partition slice Windows can automount, use partition number `0`.
Supply the expected serial in the exact `XXXX-XXXX` form printed by Windows
`vol`; the guest will not select a volume from a guessed drive letter.

## Run the mandatory read-only scan

```bash
python tooling/paired-vm/windows-forensic-vm/forensic_vm.py run \
  --mode scan \
  --official-iso /cases/CASE-001/tooling/windows-11-enterprise-25h2.iso \
  --auxiliary-image /cases/CASE-001/tooling/windows-forensic-auxiliary/windows-forensic-auxiliary.img \
  --auxiliary-media-record /cases/CASE-001/tooling/windows-forensic-auxiliary/auxiliary-media.json \
  --derivative /cases/CASE-001/repair/source-a.windows-derivative.raw \
  --derivative-descriptor /cases/CASE-001/repair/source-a.windows-derivative.raw.forensic-derivative.json \
  --volume-serial 0123-4567 \
  --partition-number 0 \
  --output /cases/CASE-001/repair/windows-scan-01
```

Review `guest/chkdsk-scan.txt`, `guest/run-status.txt`, `run.json`, `qemu.log`,
and the before/after hashes. A scan reporting filesystem problems can still be a
completed run; the gate requires guest completion and an unchanged derivative.

## Repair only the derivative

```bash
python tooling/paired-vm/windows-forensic-vm/forensic_vm.py run \
  --mode repair \
  --official-iso /cases/CASE-001/tooling/windows-11-enterprise-25h2.iso \
  --auxiliary-image /cases/CASE-001/tooling/windows-forensic-auxiliary/windows-forensic-auxiliary.img \
  --auxiliary-media-record /cases/CASE-001/tooling/windows-forensic-auxiliary/auxiliary-media.json \
  --derivative /cases/CASE-001/repair/source-a.windows-derivative.raw \
  --derivative-descriptor /cases/CASE-001/repair/source-a.windows-derivative.raw.forensic-derivative.json \
  --volume-serial 0123-4567 \
  --partition-number 0 \
  --scan-run /cases/CASE-001/repair/windows-scan-01 \
  --allow-derivative-write \
  --output /cases/CASE-001/repair/windows-repair-01
```

After repair, retry the exact parser failure against this derivative and retain
the before/after block maps even if `chkdsk` changes nothing. Never promote a
repaired derivative over an original or verified working image.

## Limitations

- The auxiliary-media discovery and answer file must be boot-tested against the
  exact 25H2 ISO and QEMU host before evidence use. A valid XML parse and command
  review do not replace a controlled boot test.
- The minimal answer file intentionally does not automate a Windows
  installation. If its command fails to launch, Setup may wait at its UI until
  the host timeout terminates the isolated VM; it has no configured install
  target.
- Windows may not automount every standalone partition slice. If so, use a
  documented whole-disk wrapper around a fresh derivative or a whole-disk
  derivative with its explicit partition number. Do not weaken serial checking.
- Changed extents are block-granular (1 MiB), not claims about particular NTFS
  records.
- Microsoft evaluation licensing and the evaluation period still apply.
- Building the Ubuntu tool image accesses Ubuntu repositories. Auxiliary-media
  creation and all evidence VM runs are network-isolated.

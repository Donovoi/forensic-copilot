# Sources and upstream references

This repository should prefer current authoritative guidance and official upstream documentation whenever tooling or forensic workflow changes.

## Forensic process references

- `NISTIR 8387` — *Digital Evidence Preservation: Considerations for Evidence Handlers* (2022)
- `NIST SP 800-86` — *Guide to Integrating Forensic Techniques into Incident Response*
- `SWGDE` — *Best Practices Apple macOS Forensic Acquisition*
- `SWGDE` — *Linux Tech Notes*
- `SWGDE` — *Model Standard Operation Procedures for Computer Forensics*
- `SWGDE` — *Requirements for Report Writing in Digital and Multimedia Forensics*
- `NIJ` / `NIST CFTT` materials for acquisition and tool-testing validation

## Tool upstreams

- `The Sleuth Kit` — <https://github.com/sleuthkit/sleuthkit>
- `Timesketch` — <https://github.com/google/timesketch>
- `Binwalk` — <https://github.com/ReFirmLabs/binwalk>
- `bulk_extractor` — <https://github.com/simsong/bulk_extractor>

## Current doc observations

- `Timesketch` official installation guidance currently references `deploy_timesketch.sh` and a service-oriented deployment model.
- `The Sleuth Kit` remains a clear upstream for filesystem and image analysis on Linux.
- `Binwalk` remains the better fit for firmware and blob analysis than for ordinary filesystem examinations.
- Windows-centric tools such as `FTK Imager`, `KAPE`, and many `Zimmerman` utilities should be treated as platform-specific rather than assumed native on Linux.

## Update discipline

When new authoritative guidance or upstream install guidance changes the recommended workflow:

1. update the relevant agent file
2. run the self-update review in `docs/self-update-loop.md`
3. update `docs/tooling-matrix.md`
4. update this file if the source basis changed materially
5. cite the new source in the resulting Markdown note or report

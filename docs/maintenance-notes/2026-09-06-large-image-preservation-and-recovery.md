# 2026-09-06 - Large-image preservation and recovery

## Trigger

Tool preparation for a large-image examination exposed reusable gaps in storage planning, durable stage reporting, deleted-file coverage, and historical contact attribution. This note records workflow lessons; it does not report a completed examination or recovered evidence.

## Files reviewed

Reviewed the large-image, preservation, inventory and catalog-recovery guides, repository instructions, README, tooling matrix, limitations, Copilot-compatible and OpenCode examiner/timeline prompts, synthetic fixtures and CI configuration. The preservation, inventory and recovery scripts each require separate independent execution review. Publication review checks generic content and documentation scope; it does not replace those safety and correctness reviews.

## Lessons and changes

- Budget the working image and recovered outputs independently, including sparse/compressed expansion, indexes, temporary files, and carving duplicates. Recheck free space before each large stage.
- Keep preservation, inventory, extraction, carving, validation, and interpretation as separately recorded stages. A running copy, successful exit, or recognized file header does not establish examination completeness.
- Gate inventory and recovery on completed preservation records, matching full hashes and byte counts, and the current working-image identity. Hold the reviewed read-only protection through child tools and retain the limitations of legacy metadata gates.
- Preserve raw inventories and complete NTFS record/type/attribute identifiers in a structured catalog. Corroborate deletion annotations against directory-entry flags; a literal filename suffix must not become a deletion finding. Keep unresolved allocation and alias conflicts explicit.
- Export bounded catalog streams with safe output names, source references, expected-size checks, independent output hashes and recorded partial attempts. Bind resume to reviewed script/tool/input identities and reject unrelated paths, aliases and hardlinks that could redirect state writes.
- Validate each tool with its own installed help, version, executable format, and provenance record. Identical option letters can mean different things across programs: `ils -z` selects likely-unused inodes, while `fls -z` selects a timezone.
- Account for deleted directories, orphan metadata, and named streams. `fls -r` cannot descend deleted directories; preserve full NTFS attribute identifiers. `icat -h` removes sparse holes and is inappropriate for faithful logical-file export.
- Prefer the smallest supported parser package. An unavailable optional integration should not block a separately verified core parser. Preserve installation and verification records privately.
- Require contextual message records for communication claims. Keep address-book entries, drafts, cached pages, raw strings, account labels, device ownership, and human attribution distinct.

The new guides and prompt references address these issues without replacing the existing specialist, script-review, report-challenge, or publication-review loops. CI exercises synthetic preservation, inventory and recovery fixtures on Windows and Linux with Python 3.10 and 3.12. These synthetic checks do not validate a particular evidence image. Actual-tool public-fixture validation is a separate controlled review record. Reviewed Python helpers use stable LF line endings across platforms so a checkout does not silently change their bytes.

## Official basis

Checked the upstream [fls](https://www.sleuthkit.org/sleuthkit/man/fls.html), [ils](https://www.sleuthkit.org/sleuthkit/man/ils.html), [icat](https://www.sleuthkit.org/sleuthkit/man/icat.html), and [tsk_recover](https://www.sleuthkit.org/sleuthkit/man/tsk_recover.html) manuals on the date of this note. The preservation guide records its Python and Windows API references separately.

## Guardrails and privacy

The reviewed guidance retains read-only evidence access, verified-copy gates, approved storage roots, controlled handling of private artifacts, independent review, and answer-oriented Markdown reporting. This note contains no case identities, source filenames, storage measurements, absolute local paths, or evidence hashes. Synthetic examples remain placeholders.

## Follow-up

Keep `docs/sources.md` and the maintenance-note index aligned with the new guidance. On the next run, check that resume/status handling remains truthful, export budgets are enforced, parser coverage is explicit, and contact examples retain source records and timestamp semantics. Treat configured CI coverage separately from successful local or remote test results, and preserve the exact reviewed script hashes in private execution records.

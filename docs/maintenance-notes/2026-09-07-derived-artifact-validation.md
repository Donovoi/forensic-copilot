# 2026-09-07 - Derived-artifact validation

## Trigger

Controlled fixture work exposed limits in native timestamp exports and the need to validate recovered artifacts without expanding image access. This note records reusable workflow changes, not case findings.

## MFT supplement

The optional exported-MFT helper authenticates an allocated export against complete recovery provenance and the original catalog, then preserves physical records, attributes and exact SI/FN values. It retains every slot, malformed field, filename attribute, sentinel and unresolved reference. Integer FILETIME rendering avoids native-export range and subsecond loss. Its output does not establish human actions, deletion dates or communications.

The helper depends on a small explicit Dissect parser set; it is distinct from the existing standard-library helpers. The requirements pin the independently reviewed versions, including an intentional development utility release. CI installs those dependencies on every Windows/Linux and Python 3.10/3.12 test job, so unavailable packages fail the check instead of hiding parser validation behind skips.

## Recovered-media worker

The Windows worker accepts only explicit hash-bound recovered outputs and their approved producer chains. It restricts media formats and local parser options, disables implicit ExifTool configuration and MOV external references, and records bounded native captures. A real external-track fixture returned exit zero after skipping its data, so any diagnostics remain incomplete even when the native exit succeeds.

Independent review exposed stale capture reuse. The approved implementation binds finalized record integrity, exact child commands and retained captures, then retries missing or changed records in new numbered attempts. Resource stops and unknown formats remain gaps. Windows synthetic tests run as a visible separate CI step; tool-dependent native validation remains a separately recorded review, not an implied CI capability.

## Integration and review

Runtime copies retain the exact independently reviewed bytes. Only test import paths change for repository layout. Generic documentation covers installation, scope, provenance gates, errors, output limits and evidence interpretation. Native public-fixture and execution approvals stay in controlled local review records; no case artifacts, output samples, machine paths or private hashes are published.

Publication/maintainer review is separate from execution review. Local synthetic checks do not establish remote CI success or validate a particular case. Recheck dependency/runtime identity and applicable coverage limits before operational use.

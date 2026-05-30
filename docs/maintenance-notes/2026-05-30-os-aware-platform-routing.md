# 2026-05-30 - OS-aware platform routing

## Trigger

Recent live-host tests used many Windows examples, which made the workflow risk sounding Windows-default even though the agent is meant to handle Windows, Linux, macOS, images, mounted filesystems, containers, servers, and derived exports.

## Accepted changes

- Added `Forensic Platform Profiler` as an internal helper for evidence OS, evidence mode, runner/evidence boundary, filesystem/logging architecture, and host-role classification.
- Wired the profiler into OpenCode and the main examiner loop.
- Updated the senior tooling specialist so platform ambiguity is resolved before OS-specific research and provisioning.
- Updated the collector and router to refuse broad OS-specific collection/routing without a platform profile.
- Added OS-first routing guidance for Windows, Linux, macOS, container/VM/cloud, and appliance-style evidence.
- Updated the source basis with platform-specific references for Microsoft event logs, systemd journal behavior, Apple unified logging, SWGDE Linux notes, and SWGDE macOS acquisition guidance.

## Validation expectation

Future tests should include at least one Windows, one Linux, and one macOS or mounted-image fixture prompt. The expected behavior is not perfect parsing; it is explicit platform classification and no OS-default artifact assumptions.

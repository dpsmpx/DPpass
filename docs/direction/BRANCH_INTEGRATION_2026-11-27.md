# Branch integration — 2026-11-27

## Baseline and scope

- Prior PR #59 head: `bc9b5c778f6a17630dc2d0b06318312891c60485`, Go/Windows #45783589405 and Android #45783579296 passed.
- New baseline: `dev/root-hotspot-zenfone` at `a0625bb8f204bbca3694edc0b26a944465eb787f`; 32 additional commits, 44 changed files, zero commits behind the prior head. Keep its entire ancestry and all D-120 test harnesses.
- Prepared command-runner change `70735057c564d0e720446783dcf02795b4ff1d2a`: the production and test Kotlin files are identical between the old PR head and hotspot baseline before applying this change. Reapply those two files; append the integration note instead of replacing the independently extended plan.

## Disposition of other branches

| Line | Decision |
|---|---|
| main, DPTS foundation/unified editor, most stacked Zapret2 diagnostics, RC1–RC6, other ancestor branches | Already ancestors of the new baseline; no duplicate merge. |
| PR #39 / feature/neural-variable-parameters-context-persistence | The divergent manual-budget dialog fix is already present in SettingsScreen. |
| build/pr34-20261121 | The two SessionRecoveryTest timing fixes are already present. The one-off delivery workflows were explicitly not intended for main. Do not restore them. |
| ccr-0315e01b-abrc7b | Keystore content detection and optional key-password fallback are already present in resign-apk.sh; no signing changes. |
| ccr-2310d434-b5rouv | Early D-26 field observations already recorded in current TODO.md; do not replace newer TODO/README. |
| claude/nice-babbage-5efint | Current geodata contract already validates attribute combinations and documents the semantics; no downgrade. |
| Independent historical APK/desktop delivery branches (apk_debug, apk-0.5.0, apk-0.6.0-dev, debug-apk, linux_debug, windows_debug) | Separate artifact-only histories, not source merge targets. Leave existing distributions untouched. |
| Old signed alpha release branches | Preserve historical tags/branches; their old versionCode, signing/publish workflow changes and routing variations are not production integration inputs. Current compiler already separates QUIC force-TCP from selected strategies. |
| PR #36 / feature/alpine-terminal-from-dpai | Existing minimal Alpine/PTY runtime is a different implementation. Full ANSI emulator and package UI remain separate optional work; do not replace the verified current runtime with the old port. |
| PR #43 / fix/doh-h2-rrset-tls-20261123 | Current Quad9 h2 support exists. Historical resolver status/full RRset diagnostic work is not identical to current fixed-DoH first-address path. Preserve research document; assess a bounded new implementation against current contracts separately. |
| PR #49 / feature/zapret2-youtube-service-evidence-20261123 | Keep original field evidence; current DPTS presets and explicit evidence admission replace old standalone buttons and implicit AUTO publication. |
| PR #50 / feature/zapret2-youtube-multiservice-fallback-20261123 | Preserve research report; old standby and wire/QUIC metrics are not blindly restored. Evaluate useful independent metrics under current request-owned diagnostics and model rules. |
| PR #56 / feature/dptest-script-engine-v080-20261124 | Preserve historical design; the old dptest grammar, multi-scenario and training implementation are not current DPTS/1. Do not add a second interpreter or old learning paths. Reassess missing useful primitives with current catalog before activating them. |

The four recovered research files are historical source records, not assertions of current capabilities. References retain the original branches/commits; no branch is deleted, no PR is closed, and no change is merged to main by this integration.

## Release gates

The new hotspot branch had no GitHub Actions run at the inspected head. Run existing PR and Android checks on the combined development branch. Keep D-120 disabled by default and retain ordinary D-51 sharing. Do not claim guest VPN, full upstream DPI integration, cross-device ROOT compatibility, or general leak prevention solely from host tests. Physical validation of guest routing, offload, DNS, IPv6, service loss, normal phone traffic, subscription and signed upgrade remains outstanding.

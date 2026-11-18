# MuyuClash Legacy Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans for integration and explicitly scoped parallel work for independent modules. Track evidence; never publish an incomplete build.

**Goal:** Build the complete on-device iOS 6 ARMv7 client specified in V3, including real traffic forwarding and recovery.

**Architecture:** Objective-C/UIKit UI talks to a root supervisor over bounded, versioned JSON Unix sockets. The supervisor owns lifecycle and capture; an unprivileged local core owns routing, DNS and protocol adapters. Configuration generations are immutable and activated only after validation and preparation succeed.

**Tech Stack:** Objective-C, C/POSIX, libyaml, clang/ld-classic, iOS SDK, launchd, Debian gzip packaging.

**Spec:** `docs/SPEC-V3.md` (user supplied, authoritative, no renewed design approval needed).

## Global Constraints

- iOS 6.0 / ARMv7 / rootful jailbreak; 256 MB design target.
- Native local processing, four UIKit tabs, white/purple colors #A99AC8 / #70558F / #F7F7F9.
- No mock state, unsupported protocol claims, silent capture downgrade or disabled TLS verification.
- No incomplete public versions. A release gate refuses packaging until target-device acceptance evidence and all required capabilities exist.
- Preserve the unrelated, dirty MuyuMusic checkout. All changes live beneath `MuyuClashLegacy/`.

## Review Focus

- A malformed or hostile imported configuration cannot crash the privileged process or execute commands.
- Failed validation/preparation retains the last active generation and node selection.
- A running proxy process never by itself implies DNS/UDP/IPv6 coverage.
- Unauthorized, oversized, truncated and stalled IPC clients cannot control or indefinitely block the daemon.
- Crash/uninstall recovery touches only state owned by this application, never flushes unrelated network rules.

### Task 1: Pin compatibility and dependencies

Files: `docs/DEPENDENCIES.md`, `third_party/manifest.json`, `docs/COMPATIBILITY.md`.

- [ ] Verify Mihomo stable tag and exact commit from upstream; pin source archive checksum.
- [ ] Inspect Senko license and protocol dependencies, including modern transports on ARMv7.
- [ ] Verify iOS 6 capture source and probe actual availability separately from declarations.
- [ ] Record build-time support and runtime evidence separately.

### Task 2: Configuration engine and immutable storage

Files: `config/MLConfig.h`, `config/MLConfig.m`, `tests/config.m`.

Interface: `+ (NSDictionary *)checkYAML:(NSString *)yaml`; result contains `valid`, `document`, `issues`, `unchecked`. Issues contain `id/category/severity/field/line/column/reason/impact/suggestion`. No silently ignored unsupported field. `MLConfigStore` imports a checked candidate, stores mode 0600, activates via rename only after core prepare acknowledgement and retains old generation on failure.

- [x] Write and run failing hostile YAML, references, unsupported transport and failed-update preservation tests.
- [x] Integrate pinned libyaml with bounded size, depth and alias handling; implement semantic validation and explicit capability registry.
- [x] Verify host behavior and iOS 6 ARMv7 compilation.

### Task 3: IPC, lifecycle and recovery boundary

Files: `ipc/MLIPC.h`, `ipc/MLIPC.m`, `supervisor/main.m`, `core/main.m`, `capture/MLCapture.h`, `capture/MLCapture.m`, `tests/ipc.m`, `tests/runtime.m`.

Wire: 4-byte network-order length followed by UTF-8 JSON, max 1 MiB. Request `{version:1,id:string,method:string,params:object}`. Reply `{version:1,id:string,result:object}` or `{version:1,id:string,error:{code:string,message:string}}`. Socket peer uid checked, 5 second timeout, absolute app-owned paths. UI calls `MLIPCRequest(path,method,params,error)` off main thread. The supervisor exposes truthful `service.status`, `system.capabilities`, `config.check`, `config.list`, `config.import`, `config.source`, `config.apply`, `config.delete`, `service.start`, `service.stop`, `service.mode`, `proxy.list`, `group.list`, `group.select`, `connections.list`, `logs.list`, `logs.clear`, `diagnostics.run`, `settings.get`, `settings.set`, `network.restore`. Unsupported methods return explicit errors; no invented metrics.

- [ ] Write/run framing, peer rejection, timeout, invalid transition and unavailable-capture startup tests.
- [ ] Implement bounded IPC, truthful states, local permission boundaries and independent recovery probe.
- [ ] Build host and ARMv7 binaries and verify Mach-O minimum OS and imports.

### Task 4: Native UI

Files: `app/main.m`, `app/MLApp.m`, `resources/Info.plist`.

Consumes IPC above. Status schema: `state`, `message`, `mode`, `activeConfig`, `coverage:{tcp,udp,ipv4,ipv6,dns}` (each string), optional measured `statistics`. List endpoints return `{items:[...]}`. Lists remain empty without data; failures are visible. All actual mutations await daemon acknowledgement.

- [ ] Implement four tabs, configuration import/editor/report, proxy/group navigation, logs/connections, settings and diagnostics using iOS 6 UIKit only.
- [x] Compile against SDK with deployment target 6.0; source uses 320x480 constraints and explicit back navigation (device layout remains unverified).
- [x] Connect real IPC and do not simulate connection/proxy/statistics state.

### Task 5: Full local traffic core and capture integration

Files: `protocols/`, `transport/`, `routing/`, `dns/`, `connections/`, `capture/`.

- [ ] Build and integrate license-reviewed protocol implementations and every required transport combination.
- [ ] Implement full ordered Mihomo rule/group/provider/DNS behavior against fixed baseline, preserving old generations for existing flows.
- [ ] Integrate verified capture backend and own-outbound exclusion, TCP/UDP/IPv6, explicit protection policies and crash recovery.
- [ ] Run necessary real protocol connections and on-device coverage/recovery checks. A probe or registry is not implementation.

### Task 6: Installation and formal release

Files: `packaging/`, `scripts/build.sh`, `scripts/release.py`, `docs/BUILD.md`, `docs/ACCEPTANCE.md`.

- [ ] Install root supervisor and unprivileged core using launchd, preserve user data on upgrades and recover before uninstall.
- [ ] Run essential installation/start/real subscription/routing/DNS/background/crash/uninstall acceptance on target device.
- [ ] Produce `.deb`, corresponding source, reproducible dependency locks, CA and license inventory only when complete.

## Execution record

2026-11-17: Existing directory is a dirty MuyuMusic repository; new product is isolated in this subdirectory. User's supplied final specification already fixes architecture and allows internal parallel work, so no repeated design questions. Current status: implementation in progress; no formal release authorized by evidence yet.

2026-11-17: Config/IPC/control/UI internal source and locked ARMv7 Senko/TLS/QUIC candidate built. Host checks and iOS artifact inspections passed; independent review fixes are recorded in `docs/PROGRESS.md`. Tasks 1/3/4 are partial; Tasks 5/6 remain incomplete. No installed forwarding executable, complete routing/DNS/capture data path, target-device acceptance or `.deb`. Build/development progress is not the completion of this plan or the V3 product.

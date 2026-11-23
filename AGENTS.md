# AGENTS.md — Hiddify Guard

## Project Overview
**Hiddify Guard** is an open-source, foolproof, fail-closed Windows Kill Switch built on native Windows Filtering Platform (`fwpuclnt.dll`) designed as a companion utility for **Hiddify (TUN mode)**.
Target audience: non-technical Windows users ("one big button, impossible to accidentally leak traffic or brick the PC").

## Tech Stack & Constraints
- **Language / Runtime:** C# / .NET 8 (`net8.0-windows`, `x64` primary target).
- **UI:** WPF (modern clean flat design, minimal dependencies, no heavy UI kits required).
- **WFP:** Direct P/Invoke to `fwpuclnt.dll` (no third-party firewall drivers, no external closed binaries).
- **Installer:** Inno Setup 6 (`installer/HiddifyGuard.iss`).
- **Config storage:** `%ProgramData%\HiddifyGuard\config.json` (shared between elevated GUI/CLI).
- **Logs:** `%ProgramData%\HiddifyGuard\logs\` (rolling simple text log, max 2 MB, never log user browsing data).

## Critical WFP Engineering Rules (DO NOT VIOLATE)
1. **Dedicated Provider & Sublayer:**
   - Use fixed, hardcoded GUIDs for `ProviderKey`, `SubLayerKey`, and deterministic/tagged filters so cleanup is 100% reliable even across restarts and upgrades.
   - Set sublayer `weight = ushort.MaxValue` (`0xFFFF`) so third-party Windows Firewall allow rules cannot bypass our block.
2. **BOOTTIME vs PERSISTENT mutual exclusion:**
   - In Windows WFP, `FWPM_FILTER_FLAG_BOOTTIME` and `FWPM_FILTER_FLAG_PERSISTENT` **CANNOT** be combined on the same filter (returns `FWP_E_INVALID_FLAGS`).
   - Implement two distinct filter sets inside a single WFP transaction (`FwpmTransactionBegin0` / `Commit0` / `Abort0`):
     - **Boot-time filters** (`flags = FWPM_FILTER_FLAG_BOOTTIME` ONLY): block all outbound IPv4 & IPv6 at `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` + permit Loopback & DHCP at boot-time.
     - **Persistent filters** (`flags = FWPM_FILTER_FLAG_PERSISTENT` ONLY, attached to our persistent sublayer): full permit/block rule set active after BFE starts.
   - On `Disable()` / `--uninstall-clean`, enumerate and remove **ALL** filters belonging to our `ProviderKey` (both persistent AND boot-time), then delete our Sublayer and Provider cleanly. Ignore `FWP_E_NOT_FOUND` (`0x80320003`) to make disable idempotent.
3. **Byte Order & Struct Layout on x64:**
   - `FWP_V4_ADDR_AND_MASK`: `addr` and `mask` MUST be in **host byte order** (`uint`, e.g., `127.0.0.1` = `0x7F000001`).
   - `FWP_V6_ADDR_AND_MASK`: `addr` is 16 bytes in **network byte order** (`byte[16]`), `prefixLength` is `byte`.
   - Ports (`FWPM_CONDITION_IP_REMOTE_PORT`, `FWPM_CONDITION_IP_LOCAL_PORT`): `FWP_UINT16` in **host byte order**.
   - AppId (`FWPM_CONDITION_ALE_APP_ID`): ALWAYS obtain via `FwpmGetAppIdFromFileName0(path, out IntPtr blob)` and free via `FwpmFreeMemory0(ref blob)`. Never construct NT device paths manually.
   - Always verify x64 alignment of `FWP_VALUE0`, `FWP_CONDITION_VALUE0`, `FWPM_FILTER_CONDITION0`, and `FWPM_FILTER0`. Use `FwpmTransactionAbort0` on any non-zero Win32/WFP status code and include hex error codes in exceptions.
4. **Mandatory Allowlist Rules (inside our sublayer, higher weights than Block All):**
   - Block all outbound IPv4 & IPv6 (`weight = 1`, lowest in sublayer).
   - Permit Loopback (`127.0.0.0/8`, `::1/128`).
   - Permit DHCP (IPv4 UDP local 68 -> remote 67; IPv6 UDP local 546 -> remote 547).
   - Permit TUN local IP addresses (`FWPM_CONDITION_IP_LOCAL_ADDRESS`) — dynamically detected Hiddify/Wintun IPv4/IPv6 addresses + safe defaults (`172.19.0.1/28`, `fdfe:dcba:9876::1/126`).
   - Permit detected Hiddify binaries (`Hiddify.exe`, `HiddifyCli.exe`, and `sing-box.exe` inside Hiddify directory if present) via `FWPM_CONDITION_ALE_APP_ID`.
   - Optional (controlled by config `AllowLan`, default `true`): Permit RFC1918 local LAN / detected physical adapter local subnet(s) + link-local (`fe80::/10`) so home printers, router admin, and local RDP keep working.
5. **Fail-Closed & Strict Manual Disable:**
   - NEVER auto-disable Kill Switch when closing the window, exiting the tray app, crashing, or rebooting.
   - Protection may ONLY be disabled by explicit user action (toggle + confirmation dialog) or CLI `--disable` / `--uninstall-clean`.
   - Uninstaller MUST call `HiddifyGuard.exe --uninstall-clean` before deleting files so users never lose internet permanently.

## UX & Localization Rules
- Auto-detect UI language from `CultureInfo.CurrentUICulture` (Russian `ru` if Russian, English `en` fallback), plus manual RU/EN switch in Advanced settings.
- Keep main window dead simple: 1 big status indicator (Green / Yellow / Gray), 1 big toggle button, and a prominent "Open Hiddify" button whenever protection is ON and Hiddify TUN is OFF.
- Closing window `[X]` hides to system tray; never disables protection.
- Single-instance app (named Mutex); launching a second instance brings the existing window to front.

## Extended plan and collaboration
- Read docs/REQUIREMENTS.md and docs/HANDOFF.md before extending the project.
- The extended PDF adds network events, explicit leak diagnostics, RU/EN resources,
  colored shields, --minimized, interactive elevated startup, CI and SHA256.
- Treat "no bytes ever" as an acceptance target, not an established guarantee.
  Unit tests and enumerated filters do not prove packet-level enforcement.
- Timeouts, missing IPv6 and unavailable targets are inconclusive. Pin direct probes
  to both physical source address and outgoing interface.
- Never disable Defender, SmartScreen, BFE, Windows Firewall or other providers.
- Live policy tests require a designated Windows VM and an operator's explicit
  authorization. Example commands in a pasted plan do not authorize host changes.
- Preserve the working Native/, Policy/, Discovery/, Storage/, Diagnostics/ boundaries.
- Give another developer one card from docs/tasks/, agree on file ownership, and
  require a diff, command results, limitations and acceptance evidence.
  Native WFP and uninstall changes need independent review.
- Do not push, publish, install startup tasks, reboot or interrupt a user's VPN
  during a source-only development task.

## Build & Verification Commands
- Build: `dotnet build src/HiddifyGuard.sln -c Release`
- Test: `dotnet test src/HiddifyGuard.sln -c Release`
- Publish self-contained x64: `dotnet publish src/HiddifyGuard.App/HiddifyGuard.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o dist/publish`

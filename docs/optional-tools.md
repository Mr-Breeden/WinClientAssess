# External Tool Installation Guide — Windows 11

**Windows Client Assessment v2.2.2**  
**Documentation reference date:** 2026-10-21 (verify upstream installer versions and requirements before downloading)

Windows Client Assessment categorizes external tools by both **dependency level** and **usage**. A tool can be useful even when the framework does not invoke it automatically.

Usage classifications:

- `INTEGRATED` — invoked directly by Windows Client Assessment.
- `INTEGRATED_FALLBACK` — used only when the primary method is unavailable.
- `MANUAL_GUIDED` — Windows Client Assessment may generate commands/guidance but does not automatically attach/instrument.
- `MANUAL` — companion tester tool, not automatically invoked.

For each tool below, the guide covers purpose, status, installation, privileges/PATH, verification, detection/override, consuming modules, and missing-tool behavior.

For first-time testers, use **GUI → Tool readiness → Configure tool location** to browse, verify, save or remove an executable override; manual JSON editing below remains supported. Missing optional/manual tools do not block WCA assessment. Detection is not a claim that all testing is complete.

## Quick support matrix

| Tool | Level / usage | Admin normally required? | PATH required? | Windows Client Assessment detection / override | If missing |
|---|---|---|---|---|---|
| 7-Zip | REQUIRED / INTEGRATED | No for install/use in normal paths; installer may prompt | No; standard Program Files checked | Detected; override key `7-Zip` | extraction capability reduced/unavailable |
| AccessChk | RECOMMENDED / INTEGRATED | Not always; protected objects may require elevation | No | Detected; `AccessChk` | reduced permission/object validation depth |
| Procmon | RECOMMENDED / INTEGRATED | Commonly yes for broad system capture | No | Detected; `Procmon` | automated runtime capture skipped; existing CSV can be used |
| Handle | RECOMMENDED / INTEGRATED | Protected processes may require elevation | No | Detected; `Handle` | reduced runtime/IPC handle evidence |
| ListDLLs | RECOMMENDED / INTEGRATED | Protected/elevated processes may require elevation | No | Detected; `ListDLLs` | raw loaded-module evidence skipped |
| PipeList | OPTIONAL / INTEGRATED_FALLBACK | Usually no; environment-dependent | No | Detected; `PipeList` | PowerShell pipe enumeration remains primary |
| Sigcheck | OPTIONAL / MANUAL | No for ordinary files | No | Detected; `Sigcheck` | no automated loss |
| Strings | OPTIONAL / MANUAL | No for accessible files | No | Detected; `Strings` | no automated loss |
| Autorunsc | OPTIONAL / MANUAL | Full system coverage benefits from elevation | No | Detected; `Autorunsc` | no automated loss |
| Process Explorer | OPTIONAL / MANUAL | Protected/elevated process inspection may require elevation | No | Detected; `Process Explorer` | no automated loss |
| TCPView/Tcpvcon | OPTIONAL / MANUAL | Usually no; some process details may be limited | No | Detected as `Tcpvcon` | no automated loss |
| lessmsi | RECOMMENDED / INTEGRATED | No for ordinary files/paths | No | Detected; `lessmsi` | MSI extraction falls back where possible |
| Detect It Easy | RECOMMENDED / INTEGRATED | No for accessible files | No | Detected; `Detect It Easy` | built-in technology heuristics remain |
| .NET SDK | Supporting prerequisite | Installer may require admin depending install scope | `dotnet` should be callable | SDK itself is not a Tool Detection row | ILSpyCmd/.NET global tools cannot be installed/updated |
| ILSpyCmd | RECOMMENDED / INTEGRATED | No | Usually yes; `%USERPROFILE%\\.dotnet\\tools` is normally added | Detected; `ILSpyCmd` | managed detection remains; automated decompilation reduced |
| dotnet-trace | OPTIONAL / MANUAL_GUIDED | Not inherently; target boundary may require elevation | Usually yes | Detected; `dotnet-trace` | generated/manual tracing workflow unavailable |
| dotnet-dump | OPTIONAL / MANUAL_GUIDED | Target boundary may require elevation | Usually yes | Detected; `dotnet-dump` | manual dump workflow unavailable |
| dotnet-counters | OPTIONAL / MANUAL_GUIDED | Not normally | Usually yes | Detected; `dotnet-counters` | manual counter workflow unavailable |
| Wireshark/Npcap | OPTIONAL / MANUAL | Npcap install/capture setup commonly requires elevation | No | Wireshark detected; `Wireshark` | manual packet capture unavailable |
| Burp Suite | OPTIONAL companion / MANUAL | No for normal use | No | **Not detected/invoked by WCA; no override key** | manual HTTP/API interception unavailable |
| WinDbg | OPTIONAL / MANUAL | Attach target may require elevation | No | Detected; `WinDbg` | manual native debugging unavailable |
| Ghidra | OPTIONAL / MANUAL | No for ordinary files | No | Detected; `Ghidra` | manual deep native RE unavailable |
| Frida | OPTIONAL / MANUAL | Attach target may require elevation | Usually yes for CLI convenience | Detected; `Frida` | manual dynamic instrumentation unavailable |

`tool_paths.json` overrides apply only to tools represented in Tool Detection. Burp Suite and the .NET SDK are documented companion/prerequisite software rather than current Tool Detection entries.

## Sysinternals Suite

**Includes relevant Windows Client Assessment tools:** Sigcheck, Strings, AccessChk, Autorunsc, Procmon, Process Explorer, TCPView/Tcpvcon, Handle, ListDLLs, PipeList.  
**Source:** https://learn.microsoft.com/sysinternals/downloads/sysinternals-suite

Microsoft distributes the Sysinternals utilities as a Suite and through the Microsoft Store. On modern Windows 11, the Store package exposes command aliases through Windows Apps; extracting the Suite ZIP into a stable `C:\Tools\Sysinternals` directory is often easier for repeatable assessment VMs and explicit path control.

### Recommended installation

1. Download the current Sysinternals Suite from Microsoft.
2. Extract it to:

```text
C:\Tools\Sysinternals
```

3. Optionally add that directory to the user/system `PATH`, or use `tool_paths.json`.
4. Accept each tool's EULA when first run, or use supported `-accepteula` options where Windows Client Assessment already does so.

### Sysinternals tools used by Windows Client Assessment

| Tool | Level | Usage | What it provides | Used by / purpose | Missing behavior |
|---|---|---|---|---|---|
| AccessChk | RECOMMENDED | INTEGRATED | Windows object/security descriptor permission inspection | named-pipe permission review and tester ACL workflows | related permission depth may be reduced |
| Procmon | RECOMMENDED | INTEGRATED | process/file/registry/network event capture | runtime capture and Procmon analysis | runtime capture can be skipped or an existing CSV supplied |
| Handle | RECOMMENDED | INTEGRATED | process handle/object inventory | runtime/IPC correlation | IPC object visibility is reduced |
| ListDLLs | RECOMMENDED | INTEGRATED | loaded module inventory | runtime loaded-DLL evidence | loaded DLL raw evidence is skipped |
| PipeList | OPTIONAL | INTEGRATED_FALLBACK | named-pipe inventory | fallback only if primary PowerShell pipe enumeration fails | PowerShell remains primary |
| Sigcheck | OPTIONAL | MANUAL | signature/version/hash inspection | tester-assisted validation; framework Authenticode uses PowerShell | no automated loss |
| Strings | OPTIONAL | MANUAL | printable-string extraction | tester-assisted binary triage | no automated loss |
| Autorunsc | OPTIONAL | MANUAL | persistence inventory | tester-assisted persistence validation | no automated loss |
| Process Explorer | OPTIONAL | MANUAL | interactive process/module/handle analysis | tester-assisted runtime review | no automated loss |
| Tcpvcon/TCPView | OPTIONAL | MANUAL | endpoint/connection inspection | tester-assisted network validation | framework uses its own network collection |

### Verification

```powershell
C:\Tools\Sysinternals\procmon64.exe /?
C:\Tools\Sysinternals\accesschk64.exe /?
C:\Tools\Sysinternals\handle64.exe /?
C:\Tools\Sysinternals\listdlls64.exe /?
C:\Tools\Sysinternals\pipelist.exe /?
```

### Overrides

```json
{
  "Procmon": "C:\\Tools\\Sysinternals\\procmon64.exe",
  "AccessChk": "C:\\Tools\\Sysinternals\\accesschk64.exe",
  "Handle": "C:\\Tools\\Sysinternals\\handle64.exe",
  "ListDLLs": "C:\\Tools\\Sysinternals\\listdlls64.exe",
  "PipeList": "C:\\Tools\\Sysinternals\\pipelist.exe"
}
```

Administrator rights are not required merely to store the binaries, but some inspection/capture scenarios require elevation to see protected processes/objects.

---

## 7-Zip

**Level:** REQUIRED  
**Usage:** INTEGRATED  
**Source:** https://www.7-zip.org/download.html

Provides general archive/installer extraction and fallback extraction when a specialized method is unavailable.

### Install

Download the current Windows x64 installer and install to the default location:

```text
C:\Program Files\7-Zip
```

### Verify

```powershell
& "C:\Program Files\7-Zip\7z.exe" i
```

### PATH / detection

PATH is optional because Windows Client Assessment checks the standard Program Files locations. Override:

```json
{"7-Zip":"C:\\Program Files\\7-Zip\\7z.exe"}
```

### Missing behavior

Tool Detection marks 7-Zip as missing/required and extraction capability is reduced or unavailable depending on installer type/other available extractors.

---

## lessmsi

**Level:** RECOMMENDED  
**Usage:** INTEGRATED  
**Source:** https://github.com/activescott/lessmsi/releases

Provides MSI-specific extraction. The project publishes Windows release ZIPs and also documents Chocolatey installation.

### Install — release ZIP

1. Download the latest release ZIP.
2. Extract all files to a stable path such as:

```text
C:\Tools\lessmsi
```

3. Verify:

```powershell
C:\Tools\lessmsi\lessmsi.exe --help
```

### Install — Chocolatey alternative

If Chocolatey is approved in the test environment:

```powershell
choco install lessmsi
```

### Detection / override

Windows Client Assessment checks PATH, common Program Files/LocalAppData/Scoop/Chocolatey locations, and WinGet package paths.

```json
{"lessmsi":"C:\\Tools\\lessmsi\\lessmsi.exe"}
```

### Missing behavior

MSI analysis still uses Windows Installer APIs; extraction falls back to 7-Zip where applicable.

---

## Detect It Easy (DiE)

**Level:** RECOMMENDED  
**Usage:** INTEGRATED  
**Source:** https://github.com/horsicq/Detect-It-Easy

Provides executable/file-format, packer/compiler, and heuristic identification. Windows Client Assessment prefers `diec.exe` for command-line integration.

### Install

Supported Windows distribution channels include the project's release packages, Chocolatey, and Microsoft Store. For repeatable assessment VMs, install/extract so `diec.exe` has a stable path.

Chocolatey alternative:

```powershell
choco install die
```

### Verify

```powershell
diec.exe --help
```

### Override

```json
{"Detect It Easy":"C:\\Program Files\\Detect It Easy\\diec.exe"}
```

### Missing behavior

Installer technology review continues using built-in signatures/heuristics; DiE-specific enrichment is skipped.

---

## .NET SDK

**Level:** Recommended prerequisite for .NET tooling  
**Usage:** Supports INTEGRATED/MANUAL_GUIDED .NET tools  
**Source:** https://dotnet.microsoft.com/download

The SDK supplies `dotnet` and the global-tool mechanism used to install ILSpyCmd and Microsoft's diagnostic tools.

### Install

Install a currently supported x64 .NET SDK for Windows from Microsoft. Use an SDK, not only a runtime, when you plan to install global tools.

### Verify

```powershell
dotnet --info
dotnet --list-sdks
```

Global tools installed with `--global` are placed under:

```text
%USERPROFILE%\.dotnet\tools
```

Microsoft documents that location as the default Windows global-tool location.

---

## ILSpy / ILSpyCmd

**Level:** RECOMMENDED (`ILSpyCmd`)  
**Usage:** INTEGRATED  
**Sources:**  
- https://github.com/icsharpcode/ILSpy  
- https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md

ILSpyCmd decompiles managed assemblies and allows Windows Client Assessment to create decompiled C# source for focused static review.

### Install ILSpyCmd

```powershell
dotnet tool install --global ilspycmd
```

Update later with:

```powershell
dotnet tool update --global ilspycmd
```

### Verify

```powershell
ilspycmd --version
ilspycmd --help
```

### Detection / override

Windows Client Assessment checks PATH and `%USERPROFILE%\.dotnet\tools` among other locations.

```json
{"ILSpyCmd":"C:\\Users\\YOUR_USERNAME\\.dotnet\\tools\\ilspycmd.exe"}
```

### Missing behavior

.NET assemblies can still be identified, but automated decompilation/source review is reduced or skipped.

The graphical ILSpy application is optional/manual and can be installed separately from the project's releases/Microsoft Store for deeper interactive review.

---

## dotnet-trace

**Level:** OPTIONAL  
**Usage:** MANUAL_GUIDED  
**Source:** https://learn.microsoft.com/dotnet/core/diagnostics/dotnet-trace

Collects EventPipe traces from running .NET processes. Windows Client Assessment does not automatically attach or collect traces; it may produce PID-specific guidance.

### Install

```powershell
dotnet tool install --global dotnet-trace
```

### Verify

```powershell
dotnet-trace --version
dotnet-trace --help
```

### Override

```json
{"dotnet-trace":"C:\\Users\\YOUR_USERNAME\\.dotnet\\tools\\dotnet-trace.exe"}
```

Administrator rights are not inherently required for ordinary supported collection, but target-process/elevation boundaries still apply.

---

## dotnet-dump

**Level:** OPTIONAL  
**Usage:** MANUAL_GUIDED  
**Source:** https://learn.microsoft.com/dotnet/core/diagnostics/dotnet-dump

Collects/analyzes .NET process dumps. Dump collection can expose sensitive in-memory data, so use it only when authorized and handle output as sensitive evidence.

### Install

```powershell
dotnet tool install --global dotnet-dump
```

### Verify

```powershell
dotnet-dump --version
dotnet-dump --help
```

### Override

```json
{"dotnet-dump":"C:\\Users\\YOUR_USERNAME\\.dotnet\\tools\\dotnet-dump.exe"}
```

### Missing behavior

Only tester-guided advanced diagnostics are unavailable; core Windows Client Assessment analysis is unaffected.

---

## dotnet-counters

**Level:** OPTIONAL  
**Usage:** MANUAL_GUIDED  
**Source:** https://learn.microsoft.com/dotnet/core/diagnostics/dotnet-counters

Provides live .NET runtime metrics/counters for tester-guided performance/runtime observation.

### Install

```powershell
dotnet tool install --global dotnet-counters
```

### Verify

```powershell
dotnet-counters --version
dotnet-counters ps
```

### Override

```json
{"dotnet-counters":"C:\\Users\\YOUR_USERNAME\\.dotnet\\tools\\dotnet-counters.exe"}
```

---

## Wireshark / Npcap

**Level:** OPTIONAL  
**Usage:** MANUAL  
**Source:** https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall.html

Provides packet capture/protocol analysis for validating endpoints/protocol behavior discovered by the client. The official Windows Wireshark installer includes Npcap, which is required for live packet capture.

### Install

1. Download the current Windows installer from https://www.wireshark.org/download.html.
2. Run the installer.
3. Keep Npcap selected if live capture is required.
4. TShark is useful for command-line analysis and can be selected during installation.

Default location is typically:

```text
C:\Program Files\Wireshark
```

### Verify

```powershell
& "C:\Program Files\Wireshark\Wireshark.exe" --version
& "C:\Program Files\Wireshark\tshark.exe" --version
```

### Override

```json
{"Wireshark":"C:\\Program Files\\Wireshark\\Wireshark.exe"}
```

### Missing behavior

No automated Windows Client Assessment module fails. Packet/protocol validation remains manual.

---

## Burp Suite

**Level:** OPTIONAL companion tool  
**Usage:** MANUAL  
**Source:** https://portswigger.net/burp/documentation/desktop/getting-started/download-and-install

Provides HTTP(S) interception, modification, replay, and (edition-dependent) scanning for client/API traffic. Burp is not auto-detected/invoked by Windows Client Assessment because its value is tester-controlled traffic interception rather than file/runtime collection.

### Install

1. Download the current Windows installer from https://portswigger.net/burp/downloads.
2. Run the installer and select/activate the appropriate Community or Professional edition.
3. Configure the target client/proxy trust settings only within the authorized assessment environment.

### Verify

Launch Burp Suite and confirm Proxy/Repeater operation. If testing TLS traffic, validate the approved certificate/proxy workflow before changing the target application.

### Missing behavior

Core Windows Client Assessment operation is unaffected; manual HTTP/API validation is unavailable through Burp until installed.

---

## WinDbg

**Level:** OPTIONAL  
**Usage:** MANUAL  
**Source:** https://learn.microsoft.com/windows-hardware/drivers/debugger/

Provides user-mode/native debugging, dump analysis, registers/memory inspection, and advanced Windows debugging.

### Install with WinGet

Microsoft documents:

```powershell
winget install Microsoft.WinDbg
```

Alternatively install via Microsoft Store/direct Microsoft installer.

### Verify

```powershell
windbgx.exe
```

or locate the installed app through Start.

### Override

```json
{"WinDbg":"C:\\Users\\YOUR_USERNAME\\AppData\\Local\\Microsoft\\WindowsApps\\WinDbgX.exe"}
```

### Privileges

Attaching to elevated/protected processes can require an elevated debugger and may be restricted by Windows security controls.

### Missing behavior

No automated Windows Client Assessment analysis fails. Advanced native debugging remains manual.

---

## Ghidra

**Level:** OPTIONAL  
**Usage:** MANUAL  
**Source:** https://github.com/NationalSecurityAgency/ghidra

Provides deep static reverse engineering/disassembly/decompilation for native binaries.

### Prerequisite

Current official Ghidra guidance requires a **64-bit JDK 21** for prebuilt releases. Follow the release's own Getting Started documentation if that requirement changes.

### Install

1. Install a supported 64-bit JDK 21.
2. Download the official prebuilt Ghidra release ZIP from the NSA GitHub releases/assets.
3. Extract it to a stable directory such as:

```text
C:\Tools\ghidra
```

4. Start:

```powershell
C:\Tools\ghidra\ghidraRun.bat
```

### Override

```json
{"Ghidra":"C:\\Tools\\ghidra\\ghidraRun.bat"}
```

### Missing behavior

No automated Windows Client Assessment module fails; deep native reverse engineering remains a tester-driven workflow.

---

## Frida

**Level:** OPTIONAL  
**Usage:** MANUAL  
**Source:** https://frida.re/docs/installation/

Provides dynamic instrumentation for authorized runtime investigation. Windows Client Assessment detects it for tester context but does **not** automatically inject/attach instrumentation.

### Install

Frida's official documentation recommends Python 3.x and:

```powershell
python -m pip install frida-tools
```

If installed inside Windows Client Assessment's virtual environment, activate that environment before invoking Frida. If you want Frida globally available to your testing account, use a dedicated approved Python environment rather than mixing unrelated project dependencies.

### Verify

```powershell
frida --version
frida-ps --help
```

### Override

```json
{"Frida":"C:\\Path\\To\\Python\\Scripts\\frida.exe"}
```

### Privileges / safety

Attaching to elevated or protected processes can require elevation and may alter target behavior. Use only when the engagement permits runtime instrumentation.

### Missing behavior

Core Windows Client Assessment operation is unaffected.

---

## Clean-VM verification checklist

After installing the tools desired for your assessment VM:

```text
[ ] python --version
[ ] python -c "import rich, pefile, psutil"
[ ] powershell/pwsh launches
[ ] 7z.exe detected
[ ] accesschk64.exe detected (recommended)
[ ] procmon64.exe/procmon.exe detected (recommended)
[ ] handle64.exe/handle.exe detected (recommended)
[ ] listdlls64.exe/listdlls.exe detected (recommended)
[ ] diec.exe detected (recommended)
[ ] lessmsi.exe detected (recommended for MSI extraction)
[ ] dotnet --info succeeds
[ ] ilspycmd --version succeeds (recommended for .NET)
[ ] optional manual tools installed as required by scope
[ ] python .\wca.py starts and Tool Detection paths look correct
[ ] tool_paths.json contains only intentional custom overrides
[ ] clean VM snapshot created after tool installation and before target installation
```

If Tool Detection shows a valid executable under a Microsoft Store/WinGet/WindowsApps path, an explicit override is not required unless the alias does not execute correctly in your environment.

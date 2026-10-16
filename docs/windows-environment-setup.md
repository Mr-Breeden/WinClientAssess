# WCA v2.2.0 — Clean Windows 11 Assessment VM Setup Guide

**Applies to:** WCA v2.2.0, Windows 11 x64, PowerShell, authorized thick-client security assessments  
**Scope:** Preparation, tool installation, detection and validation. This guide ships with the WCA v2.2.0 source release.

> WCA does not automatically execute PoCs or install/launch/exercise assessment targets. Install external analysis tools from approved sources and retain a clean VM snapshot. Do not disable endpoint protections by default.

## 1. Prepare a clean Windows 11 VM

1. Provision a Windows 11 x64 VM (VMware, Hyper-V, or your authorized hypervisor). Apply Windows updates and install VM integration tools as needed.
2. Use a dedicated tester account and isolated/approved network access. Retain administrator credentials for tools that need elevation; do not run everything elevated unnecessarily.
3. Allow generous free disk space. Decompiled .NET source, before/after inventories and **temporary full-host Procmon traces** can grow substantially. Plan storage according to the target and capture duration; the framework does not guarantee a fixed capacity requirement.
4. Create `C:\Tools` for manually installed utilities, `C:\Assessments` for results and a separate location for target packages; adjust locations to the engagement's handling requirements.
5. Take a **clean OS snapshot** after patching and before target installation.

## 2. Install core prerequisites

| Software | Required? | Purpose | Source / installation |
|---|---|---|---|
| Python **3.10+** (x64) | Yes | WCA CLI and collectors | https://www.python.org/downloads/windows/ |
| Windows PowerShell | Yes | Windows-native inspection and collectors | Included with Windows 11; confirm PowerShell runs |
| 7-Zip (x64) | Required by WCA tool detection | Archive/package extraction | https://www.7-zip.org/download.html |
| WCA v2.2.0 source release | Yes | Assessment engine, modules and documentation | Approved WCA release ZIP |
| .NET SDK (supported x64 release) | Recommended for managed targets | Installs ILSpyCmd and .NET diagnostics | https://dotnet.microsoft.com/download |

Install Python with the launcher `py.exe` available. Install 7-Zip to the normal location (`C:\Program Files\7-Zip\7z.exe`) unless you have an organizational standard. Verify:

```powershell
py --version
Get-Command powershell.exe
& 'C:\Program Files\7-Zip\7z.exe' i
```

**Note:** Windows PowerShell execution policy or organizational application controls may block local scripts. Follow your organization's policy for signed/approved scripts; don't disable protections globally merely to run WCA.

## 3. Extract WCA and install Python dependencies

Open PowerShell in the **extracted** WCA v2.2.0 directory (not inside the ZIP):

```powershell
.\install_dependencies.ps1
.\.venv\Scripts\Activate.ps1
python .\wca.py --version
python .\wca.py --backend-action capabilities
```

From a normal PowerShell session, `python .\wca.py --gui` requests UAC Administrator elevation and then starts the local GUI in a **new elevated console**. If UAC is cancelled the GUI remains stopped. An Administrator PowerShell launch skips the prompt.

The installer creates `.venv`, updates pip and installs `rich`, `pefile`, and `psutil`. It checks for 7-Zip, but does **not** install the external utilities in the sections below.

Alternatively:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

**Regression tests only:** To install pytest and all the optional test requirements in the same virtual environment, use:

```powershell
.\install_dependencies.ps1 -TestDependencies
python -m pytest -q
```

For regular assessments, `install_dependencies.ps1` without `-TestDependencies` does not install pytest.

## 4. Install recommended integrated tools

These add the most value to a normal full WCA assessment. Install them from official project releases or your approved internal package repository.

| Tool | Importance | How to install / verify | Integration |
|---|---|---|---|
| **Sysinternals Suite** | Recommended | Download from https://learn.microsoft.com/sysinternals/downloads/sysinternals-suite, extract to `C:\Tools\Sysinternals` | Provides Procmon, AccessChk, Handle, ListDLLs, PipeList and other utilities |
| **lessmsi** | Recommended for MSI targets | https://github.com/activescott/lessmsi/releases ; extract to `C:\Tools\lessmsi` | MSI extraction |
| **Detect It Easy** (`diec.exe`) | Recommended | https://github.com/horsicq/Detect-It-Easy ; choose a Windows package with CLI | Binary and compiler/packer identification |
| **ILSpyCmd** | Recommended for .NET targets | Install supported .NET SDK, then `dotnet tool install --global ilspycmd` | Managed assembly decompilation |

Key Sysinternals files to verify in `C:\Tools\Sysinternals`: `procmon64.exe` (or available Procmon executable), `accesschk64.exe`, `handle64.exe`, `listdlls64.exe`, `pipelist.exe`. Other Sysinternals manual companions include `sigcheck64.exe`, `strings64.exe`, `autorunsc64.exe`, `procexp64.exe` and `tcpvcon64.exe`.

Run checks after installing these tools:

```powershell
Test-Path 'C:\Tools\Sysinternals\procmon64.exe'
Test-Path 'C:\Tools\Sysinternals\accesschk64.exe'
Test-Path 'C:\Tools\Sysinternals\handle64.exe'
Test-Path 'C:\Tools\Sysinternals\listdlls64.exe'
Test-Path 'C:\Tools\lessmsi\lessmsi.exe'
dotnet --info
ilspycmd --version
```

Some Sysinternals utilities present first-run license prompts and some capture/inspection actions require administrative rights. WCA handles supported acceptance flags during integrated invocations, but test the actual executable's ability to run in your environment.

## 5. Optional tools by assessment need

| Tool | When to install | Integration mode |
|---|---|---|
| **Wireshark + Npcap** — https://www.wireshark.org/download.html | Network protocol and packet validation | Manual |
| **Burp Suite** — https://portswigger.net/burp/downloads | HTTP(S)/API traffic interception | Manual companion; not automatically detected by WCA |
| **WinDbg** — https://learn.microsoft.com/windows-hardware/drivers/debugger/ | Native debugger, crash and memory analysis | Manual |
| **Ghidra** — https://github.com/NationalSecurityAgency/ghidra | Native static reverse engineering | Manual; follow the specific release's Java requirements |
| **Frida** — https://frida.re/docs/installation/ | Advanced runtime instrumentation | Manual; install in an approved Python environment |
| **dotnet-trace / dotnet-dump / dotnet-counters** | Deeper managed-runtime validation | Manual-guided |
| **Process Explorer, Sigcheck, Strings, Autorunsc, TCPView** | Manual verification workflows | Included with Sysinternals Suite |

Install optional .NET diagnostics, if wanted:

```powershell
dotnet tool install --global dotnet-trace
dotnet tool install --global dotnet-dump
dotnet tool install --global dotnet-counters
```

For Frida, avoid mixing assessment runtime dependencies with unrelated global Python packages unless that's intentional. In a separate approved environment, `python -m pip install frida-tools` is the documented installation route. WCA does not automatically attach/inject with Frida.

## 6. Configure executable discovery only if necessary

WCA detects tools from PATH and several common install locations, including WindowsApps aliases. First inspect the tool-detection table when launching `python .\wca.py` or use:

```powershell
python .\wca.py --backend-action tool_readiness
```

If a supported tool is not found, copy `tool_paths.example.json` to `tool_paths.json` in the WCA source directory, **remove all examples you do not need**, and provide paths only for missing tools, e.g.:

```json
{
  "Procmon": "C:\\Tools\\Sysinternals\\procmon64.exe",
  "AccessChk": "C:\\Tools\\Sysinternals\\accesschk64.exe",
  "Handle": "C:\\Tools\\Sysinternals\\handle64.exe",
  "ListDLLs": "C:\\Tools\\Sysinternals\\listdlls64.exe",
  "lessmsi": "C:\\Tools\\lessmsi\\lessmsi.exe"
}
```

Adjust executable names to the exact official ZIP contents and your environment. WCA's Tool Detection table is the authoritative check for what it recognizes, and an alias resolving to the correct binary may require no override.

## 7. Validate the installed environment

In the WCA v2.2.0 directory with `.venv` activated:

```powershell
python -c "import rich,pefile,psutil; print('Core Python dependencies OK')"
python .\wca.py --version
python .\wca.py --backend-action capabilities
python .\wca.py --backend-action tool_readiness
python .\wca.py
```

On the interactive CLI, check the **Tool Detection** table. Confirm required tools are `FOUND`, recommended integrations you installed are `FOUND`, and missing manual-only tools show expected optional coverage limitations. For release validation, install test dependencies explicitly with `.\install_dependencies.ps1 -TestDependencies` or `python -m pip install -r requirements-dev.txt` before running `python -m pytest -q`.

**v2.2.0 validation:** `scripts/validate_windows.ps1` explicitly checks each Python exit code and fails closed if a command fails.

## 8. Take your ready-to-test snapshot

Before assessment activity:

- [ ] Windows patched; tester identity and working folders configured
- [ ] Python and WCA dependencies verified
- [ ] PowerShell available; 7-Zip detected
- [ ] Procmon / AccessChk / Handle / ListDLLs detected for full-mode collection
- [ ] lessmsi and Detect It Easy detected if applicable
- [ ] .NET SDK / ILSpyCmd detected for managed applications
- [ ] Optional tools installed according to testing scope
- [ ] `tool_paths.json` contains only necessary overrides
- [ ] Sufficient storage for temporary capture and extracted files
- [ ] Snapshot taken with **tools installed but before the target is installed or launched**

Then start with `python .\wca.py`, select **installable** or **portable** and **static** or **full**. During full mode, WCA collects the baseline and pauses for **tester-controlled** installation/activity. Run Guided Runtime Observation separately when needed. Preserve assessment archives and manifests; export the sanitized Client Appendix only after Guided Review is complete and integrity checks pass.

## 9. Troubleshooting and supporting documentation

- `docs/installation.md` — concise built-in installation reference
- `docs/optional-tools.md` — exhaustive per-tool instructions and tool override keys (updated for this release)
- `docs/troubleshooting.md` — collector and evidence-handling issues
- `docs/windows-validation.md` — Windows acceptance test plan (requires opt-in `requirements-dev.txt`)
- `tool_paths.example.json` — canonical detection override-key examples
- `README.md` — commands and assessment lifecycle

This guide describes the shipped v2.2.0 behavior; tool vendors' installers and support requirements can change. Confirm current upstream instructions and your organization's software approval policy before installing externally sourced binaries.

### v2.2.0 validation and readable backend

The local `tool_paths.json` file is expected when testers configure non-default tool locations; `scripts/validate_windows.ps1` will not reject that file. WCA release packaging still excludes it. For readable manual checks use `python .\wca.py --backend-action tool_readiness --backend-format text`. JSON remains the default for machine integrations.

## v2.2.0 clean-install acceptance record

On the fresh Windows 11 VM, record the WCA `--version` output, PowerShell version, Python version, required/recommended Tool Readiness results, successful `validate_windows.ps1` completion, and a brief GUI workflow result. The tool displays detected utilities; where executable version metadata cannot be verified, it reports **Not verified** rather than guessing. Elevated permissions may be needed for native Windows capture and symlink security-regression tests; follow enterprise policy. Never package `tool_paths.json`, tester private paths, output folders, or target binaries with WCA.

See [Windows Acceptance](windows-validation.md) for the two-machine test plan and [GUI Guide](gui-guide.md) for complete browser workflow controls.

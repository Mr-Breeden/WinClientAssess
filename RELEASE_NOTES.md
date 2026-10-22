# WinClientAssess (WCA) v2.2.2 — Production Release

![WinClientAssess Windows Client Assessment release image](https://github.com/Mr-Breeden/WinClientAssess/releases/download/v2.2.2/WinClientAssess-Security-Dashboard.png)

<!-- Banner is a planned release asset URL. It will render only after publishing the v2.2.2 release and uploading the approved PNG under that exact filename. -->

**Framework:** `2.2.2` · **Methodology:** `1.9` · **Artifact catalog:** `2.0` · **Platform:** Windows 11

WCA supports authorized static and full security assessments of Windows MSI/EXE and portable thick-client applications. This release improves tester setup, evidence review and workflow clarity while preserving established collection, Guided Runtime, and Client Appendix functionality.

## What's improved

- **Tool Readiness:** Set existing supported tool executable locations through the GUI; save, verify, or remove local overrides without downloading programs.
- **Testing Queue report viewer:** Open linked reports inline, search literal terms, jump between matches, and copy paths or optional read-only PowerShell search commands. Clipboard search is enabled only after a search term is supplied.
- **Evidence integrity awareness:** The viewer reminds testers that modifying collected originals can invalidate protected assessment evidence.
- **Usability and applicability:** Clearer assessment-start validation, Static-versus-runtime progress, MSI review shortcuts, and explanations of excluded manual cases.
- **Retained workflows:** Windows UAC elevation, Full/Static assessment modes, target-scoped collection, Guided Runtime, independent manual/WCR reviews, verification and privacy-conscious Client Appendix generation.

## Validation

The underlying production build completed 515 portable regressions in three nonoverlapping batches (172 + 172 + 171), source/ZIP audits and clean-extraction checks in the previous build environment. A full Windows 11 v2.2.2 assessment and Client Appendix were subsequently tested by the assessor with **no issues reported**. Every recorded reviewer answer in that assessment was synthetic test input; it does **not** substantiate actual vulnerabilities in the assessed application.

This GitHub-upload tester distribution preserves functional collectors and workflows from that tested build. The final archive additionally simplifies release history, removes a stale version label from generated HTML instructions, and updates onboarding documentation. The revised ZIP received clean-extraction and portable smoke checks. Full Windows release-script regression tests require the original full-source archive and are not claimed as re-run here.

## Installation

Extract `WCA-v2.2.2-Tester.zip` into a trusted folder on Windows 11 and run:

```powershell
.\install_dependencies.ps1
python .\wca.py --version
python .\wca.py --gui
```

Approve the UAC prompt when appropriate. Keep the local GUI's `#session=` URL fragment private. Use the Tester Workspace for Guided Runtime, inline technical reports, manual testing and the Client Appendix. Prior-version assessments may be available for read-only verification, but new runtime collection requires a compatible same-version assessment.

## Release files

- `WCA-v2.2.2-Tester.zip` — complete functional Windows tester distribution, including operational Python source, GUI, utility modules, documentation and PoC helper resources; **not** the developer regression suite.
- `WinClientAssess-Security-Dashboard.png` — approved, version-free promotional banner. Displayed metrics are illustrative.
- `WCA-v2.2.2-SHA256SUMS.txt` — hashes of included release assets.

The separately built `WCA-v2.2.2.zip` full-source/regression archive is **not** included in this upload bundle because its original bytes were not available for final repackaging. It must be added and checked independently before claiming a complete source + tester release set.

Release tag, repository source update and GitHub publication require separate approval. Lee's optional recursive ACL enumeration suggestion is deferred and not part of v2.2.2.

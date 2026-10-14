# WCA v2.0.5 — Getting Started

Start here for a concise walkthrough. For a new computer, follow [Clean Windows 11 VM Setup](windows-environment-setup.md) before these steps.

1. Extract `WCA-v2.0.5.zip` into a local folder. Open **Windows PowerShell** in that folder; use an elevated session for Full mode/Procmon where required. Use a disposable VM snapshot before target installation.
2. Run ` .\install_dependencies.ps1 ` to install Python dependencies and verify 7-Zip. Install recommended external tools as described in [Optional Tools](optional-tools.md); configure a private `tool_paths.json` if WCA cannot find an executable automatically.
3. Launch `python .\wca.py --gui`, leaving the hosting console running. WCA displays a private `http://127.0.0.1:9001/#session=...` URL. The GUI remains local; never share its access URL.
4. Open **New Assessment**. Select installer (MSI/EXE) or portable target, Static/Full mode, output directory, and desired checkboxes. Static mode collects package evidence only. Full mode takes a baseline snapshot and waits for your explicit manual installation/activity confirmation.
5. Open **Overview** to monitor the background worker and runtime collection. For additional evidence, select **Guided Runtime Observation** on a completed same-version Full assessment, manually exercise the target, then click **Stop Capture** (the **Stop Guided Runtime Observation** button).
6. In **Guided Review**, use the existing ten-section guidance to validate each candidate. Save an appropriate disposition and optional notes; never label a condition a proven vulnerability merely because the tool surfaced it.
7. Confirm **Assessment Management** reports integrity PASS. Only after review is complete, explicitly export a sanitized **Client Appendix**; inspect it before sharing.

**CLI alternative:** `python .\wca.py`. **Test environment:** ` .\install_dependencies.ps1 -TestDependencies ` followed by ` .\scripts\validate_windows.ps1 `. **Help:** [GUI Guide](gui-guide.md), [Troubleshooting](troubleshooting.md), [Windows Validation](windows-validation.md).

WCA never installs, launches, authenticates to, or exploits target software automatically. It also does not execute supplied PoCs. Cross-version assessment writes are blocked even when old evidence can be read.

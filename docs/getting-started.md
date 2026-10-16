# WCA v2.2.0 — Getting Started

Start here for a concise walkthrough. For a new computer, follow [Clean Windows 11 VM Setup](windows-environment-setup.md) before these steps.

1. Extract `WCA-v2.2.0-Tester.zip` into a local folder. Open **Windows PowerShell** in that folder. Starting the GUI requests Administrator elevation through Windows UAC when needed; approving opens a new elevated WCA console. Static CLI and read-only commands do not require elevation. Use a disposable VM snapshot before target installation.
2. Run ` .\install_dependencies.ps1 ` to install Python dependencies and verify 7-Zip. Install recommended external tools as described in [Optional Tools](optional-tools.md); configure a private `tool_paths.json` if WCA cannot find an executable automatically.
3. Launch `python .\wca.py --gui`, leaving the WCA console running (the **new elevated window** if UAC was approved). WCA displays a private `http://127.0.0.1:9001/#session=...` URL. The GUI remains local; never share its access URL.
4. Open **New Assessment**. Select installer (MSI/EXE) or portable target, Static/Full mode, output directory, and desired checkboxes. Static mode collects package evidence only. Full mode takes a baseline snapshot and waits for your explicit manual installation/activity confirmation.
5. Open **Overview** to monitor the background worker and runtime collection. For additional evidence, select **Guided Runtime Observation** on a completed same-version Full assessment, manually exercise the target, then click **Stop Capture** (the **Stop Guided Runtime Observation** button).
6. In **Tester Workspace > Testing Queue**, review the applicable test activity and each of its linked WCR cards; candidate dispositions and manual completion remain independent. Use Pending Guided Review and Pending Manual Testing filters to find outstanding work. The ten-section candidate guidance remains available in the WCR cards. Do not repeat procedures by following the optional Evidence & Guidance references as another checklist.
7. Confirm **Assessment Management** reports integrity PASS. In **Final Checklist**, reconcile any remaining testing and explicitly generate a sanitized **Client Appendix**. WCA re-verifies integrity during export; inspect deliverables before sharing.

**CLI alternative:** `python .\wca.py`. **Test environment:** ` .\install_dependencies.ps1 -TestDependencies ` followed by ` .\scripts\validate_windows.ps1 `. **Help:** [GUI Guide](gui-guide.md), [Troubleshooting](troubleshooting.md), [Windows Validation](windows-validation.md).

WCA never installs, launches, authenticates to, or exploits target software automatically. It also does not execute supplied PoCs. Cross-version assessment writes are blocked even when old evidence can be read.

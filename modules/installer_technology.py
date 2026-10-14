from __future__ import annotations
from utils.assessment_layout import artifact_path

from pathlib import Path
from utils.command_runner import run_command

SIGNATURES = [
    ("WiX Burn", [b"WixBundle", b"Burn v", b"WixStdBA"]),
    ("Inno Setup", [b"Inno Setup Setup Data", b"Inno Setup"]),
    ("NSIS", [b"Nullsoft Install System", b"NSIS"]),
    ("InstallShield", [b"InstallShield"]),
    ("Advanced Installer", [b"Advanced Installer"]),
    ("Squirrel", [b"SquirrelAwareVersion", b"Squirrel"]),
    ("Electron", [b"electron.exe", b"Electron Framework"]),
]


def _signature_detect(path: Path, prefix_data=None):
    if path.suffix.lower() == ".msi":
        return ["Windows Installer (MSI)"]
    if prefix_data is not None:
        data = bytes(prefix_data)
    else:
        try:
            with path.open("rb") as fh:
                data = fh.read(32 * 1024 * 1024)
        except Exception:
            return []
    lower = data.lower()
    hits = []
    for name, signatures in SIGNATURES:
        if any(signature.lower() in lower for signature in signatures):
            hits.append(name)
    return hits


def run_installer_technology(installer: Path, assessment_dir: Path, tools, prefix_data=None):
    hits = _signature_detect(installer, prefix_data)
    die_output = ""
    die_path = tools.get("Detect It Easy", {}).get("path")
    if die_path and Path(die_path).stem.lower() == "diec":
        result = run_command([die_path, str(installer)], timeout=60)
        die_output = (result.get("stdout", "") + "\n" + result.get("stderr", "")).strip()

    lines = [
        "Installer Technology Review",
        "=" * 27,
        "",
        f"Installer: {installer}",
        "",
        "Built-in detections: " + (", ".join(hits) if hits else "No known installer signature matched"),
    ]
    if die_output:
        lines += ["", "[Detect It Easy CLI]", die_output]
    elif die_path:
        lines += ["", "Detect It Easy GUI was detected; diec.exe is preferred for automation."]
    else:
        lines += ["", "Detect It Easy CLI was not detected."]

    (artifact_path(assessment_dir, "installer_technology.txt")).write_text("\n".join(lines) + "\n", encoding="utf-8")
    status = "PASS" if hits or die_output else "WARN"
    details = ", ".join(hits) if hits else ("DiE output captured" if die_output else "Technology not conclusively identified")
    return {"status": status, "details": details, "technologies": hits, "die_output": die_output}

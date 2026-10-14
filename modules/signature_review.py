from utils.assessment_layout import artifact_path
from pathlib import Path
from utils.powershell import run_powershell_json
from utils.report_format import header, kv, bool_text


def run_signature_review(target_file: Path, assessment_dir: Path, target_label: str = "Selected target"):
    safe = str(target_file).replace("'", "''")
    ps = f"""
    $s = Get-AuthenticodeSignature -LiteralPath '{safe}' -ErrorAction Stop
    if($null -eq $s) {{ throw 'Get-AuthenticodeSignature returned no result.' }}
    [PSCustomObject]@{{
      Status=[string]$s.Status; StatusMessage=$s.StatusMessage;
      SignerSubject=if($s.SignerCertificate){{$s.SignerCertificate.Subject}}else{{$null}};
      SignerIssuer=if($s.SignerCertificate){{$s.SignerCertificate.Issuer}}else{{$null}};
      Thumbprint=if($s.SignerCertificate){{$s.SignerCertificate.Thumbprint}}else{{$null}};
      NotBefore=if($s.SignerCertificate){{$s.SignerCertificate.NotBefore}}else{{$null}};
      NotAfter=if($s.SignerCertificate){{$s.SignerCertificate.NotAfter}}else{{$null}};
      TimeStamperSubject=if($s.TimeStamperCertificate){{$s.TimeStamperCertificate.Subject}}else{{$null}}
    }}
    """
    data, result = run_powershell_json(ps)
    width=104
    status = str(data.get("Status") or "").strip() if isinstance(data, dict) else ""
    if not isinstance(data, dict) or not status:
        error = str(result.get("stderr") or result.get("stdout") or "No signature status was returned.").strip()
        lines=header(
            "Windows Client Assessment - Digital Signature Review",
            ["Validates Windows Authenticode signature information for the selected target file."],width
        )
        lines += ["Status: UNAVAILABLE", "", error]
        (artifact_path(assessment_dir, "signature_review.txt")).write_text("\n".join(lines).rstrip()+"\n",encoding="utf-8")
        return {"status":"ERROR","details":f"Authenticode query unavailable: {error}"}

    timestamped=bool(data.get("TimeStamperSubject"))
    lines=header(
        "Windows Client Assessment - Digital Signature Review",
        ["Validates Windows Authenticode signer, certificate validity window, and timestamp information."],width
    )
    lines += [
        "SUMMARY","-"*width,
        kv("Signature Status",status),
        kv("Valid",bool_text(status.lower()=="valid")),
        kv("Timestamped",bool_text(timestamped)),
        kv("Signer",data.get("SignerSubject")),
        "",
        "CERTIFICATE DETAILS","-"*width,
        kv("Signer Subject",data.get("SignerSubject")),
        kv("Signer Issuer",data.get("SignerIssuer")),
        kv("Thumbprint",data.get("Thumbprint")),
        kv("Valid From",data.get("NotBefore")),
        kv("Valid Until",data.get("NotAfter")),
        kv("Timestamp Signer",data.get("TimeStamperSubject")),
        kv("Status Message",data.get("StatusMessage")),
    ]
    (artifact_path(assessment_dir, "signature_review.txt")).write_text("\n".join(lines).rstrip()+"\n",encoding="utf-8")
    if status.lower()!="valid":
        return {"status":"WARN","details":f"Signature status: {status}","findings":[{
            "title":"Digital Signature Requires Review","severity":"Informational",
            "description":f"{target_label} did not return a Valid Authenticode signature status. This is a point of interest requiring context.",
            "evidence":f"Get-AuthenticodeSignature status: {status}",
            "recommendation":"Confirm target provenance and determine whether code signing is expected for the product or distribution channel."
        }]}
    return {"status":"PASS","details":"Authenticode signature valid"}

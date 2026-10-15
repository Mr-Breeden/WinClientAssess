from pathlib import Path

import modules.privilege_boundary_review as pb
import modules.updater_security_review as up


class FakeAclCache:
    def __init__(self, writable_contains=()):
        self.writable_contains = tuple(x.lower() for x in writable_contains)
    def get_many(self, paths, batch_size=75):
        return {str(p).lower(): self._row(p) for p in paths}
    def get(self, path):
        return self._row(path)
    def _row(self, path):
        writable = any(token in str(path).lower() for token in self.writable_contains)
        access = ([{"Identity": "BUILTIN\\Users", "Rights": "Modify", "Type": "Allow", "Inherited": False}] if writable else [])
        return {"Path": str(path), "Exists": True, "Owner": "SYSTEM", "Access": access}


def test_privilege_boundary_enumerates_unquoted_service_candidates(tmp_path):
    diff = {"Services": {"added": [{"Name": "WidgetSvc", "DisplayName": "Widget", "StartName": "LocalSystem", "PathName": r"C:\Program Files\Widget App\service.exe"}]}, "ScheduledTasks": {"added": []}, "RunEntries": {"added": []}, "Filesystem": {"added": []}}
    result = pb.run_privilege_boundary_review(tmp_path, diff, {}, [], FakeAclCache((r"c:\program files",)))
    assert any("writable intermediate candidate" in r["Issue"] for r in result["records"])
    report = (tmp_path / "privilege_boundary_review.txt").read_text(encoding="utf-8")
    assert r"C:\Program Files\Widget.exe" in report


def test_updater_staged_package_includes_signature_state(tmp_path, monkeypatch):
    candidate = {"Path": r"C:\Program Files\Widget\updater.exe", "Source": "installed differential", "LaunchContexts": [{"Type": "Service", "Component": "WidgetUpdater", "Account": "LocalSystem", "RunLevel": ""}]}
    stage = r"C:\Users\Public\Widget\update.exe"
    diff = {"Filesystem": {"added": [{"Path": stage, "IsDirectory": False}], "changed": []}, "Services": {"added": []}, "ScheduledTasks": {"added": []}}
    monkeypatch.setattr(up, "_discover_artifacts", lambda *args, **kwargs: [{"Path": stage, "Source": "Filesystem added", "IsDirectory": False, "Kind": "Package/Executable", "Process": "", "Operation": "", "Result": "", "Detail": ""}])
    monkeypatch.setattr(up, "_signature_batch", lambda paths: {str(p).lower(): {"Path": p, "Exists": True, "Status": ("NotSigned" if "update.exe" in str(p).lower() and "public" in str(p).lower() else "Valid"), "StatusMessage": "", "SignerSubject": None, "Timestamped": False} for p in paths})
    result = up.run_updater_security_review(tmp_path, [candidate], diff, {}, {}, [], "full", True, FakeAclCache((r"users\public",)))
    assert any(p["Category"] == "Package Integrity" for p in result["updater_pois"])
    text = (tmp_path / "updater_staging_review.txt").read_text(encoding="utf-8")
    assert "Signature Status" in text and "NotSigned" in text


class AppendOnlyAclCache(FakeAclCache):
    def _row(self, path):
        access = [{"Identity": "NT AUTHORITY\\Authenticated Users", "Rights": "AppendData", "Type": "Allow", "Inherited": False}]
        return {"Path": str(path), "Exists": True, "Owner": "SYSTEM", "Access": access}


class CreateFilesAclCache(FakeAclCache):
    def _row(self, path):
        access = [{"Identity": "NT AUTHORITY\\Authenticated Users", "Rights": "CreateFiles", "Type": "Allow", "Inherited": False}]
        return {"Path": str(path), "Exists": True, "Owner": "SYSTEM", "Access": access}


def test_unquoted_service_appenddata_does_not_prove_intermediate_exe_creation(tmp_path):
    diff = {"Services": {"added": [{"Name": "WidgetSvc", "DisplayName": "Widget", "StartName": "LocalSystem", "PathName": r"C:\Program Files\Widget\service.exe"}]}, "ScheduledTasks": {"added": []}, "RunEntries": {"added": []}, "Filesystem": {"added": []}}
    result = pb.run_privilege_boundary_review(tmp_path, diff, {}, [], AppendOnlyAclCache())
    unquoted = [r for r in result["records"] if "Unquoted SYSTEM service path" in r["Issue"]]
    assert len(unquoted) == 1
    assert unquoted[0]["Confidence"] == "MEDIUM"
    assert "requires intermediate-path validation" in unquoted[0]["Issue"]
    assert "CreateFile=0" in unquoted[0]["Evidence"]


def test_unquoted_service_createfiles_can_promote_intermediate_candidate(tmp_path):
    diff = {"Services": {"added": [{"Name": "WidgetSvc", "DisplayName": "Widget", "StartName": "LocalSystem", "PathName": r"C:\Program Files\Widget\service.exe"}]}, "ScheduledTasks": {"added": []}, "RunEntries": {"added": []}, "Filesystem": {"added": []}}
    result = pb.run_privilege_boundary_review(tmp_path, diff, {}, [], CreateFilesAclCache())
    unquoted = [r for r in result["records"] if "Unquoted SYSTEM service path" in r["Issue"]]
    assert len(unquoted) == 1
    assert unquoted[0]["Confidence"] == "HIGH"
    assert "writable intermediate candidate" in unquoted[0]["Issue"]

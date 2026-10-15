from pathlib import Path
import importlib.util

from utils.artifacts import ARTIFACTS
from utils.artifact_policy import LEGACY_GENERATED_FILES


def _load_packager():
    path = Path('scripts/package_release.py').resolve()
    spec = importlib.util.spec_from_file_location('wca_package_release', path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def test_release_tree_has_only_current_validation_and_no_generated_build_artifacts():
    packager = _load_packager()
    assert packager.audit_tree() == []
    assert Path('scripts/validate_windows.ps1').is_file()
    assert not list(Path('scripts').glob('validate_windows_*.ps1'))
    assert not list(Path('.').glob('*.egg-info'))
    assert not Path('examples').exists()


def test_retired_duplicate_service_task_indexes_are_not_current_artifacts():
    filenames = {spec['filename'] for spec in ARTIFACTS.values()}
    assert 'new_services.txt' not in filenames
    assert 'new_scheduled_tasks.txt' not in filenames
    assert {'new_services.txt', 'new_scheduled_tasks.txt'} <= LEGACY_GENERATED_FILES
    assert 'services_review.txt' in filenames
    assert 'scheduled_tasks_review.txt' in filenames

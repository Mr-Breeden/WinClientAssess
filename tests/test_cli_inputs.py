import argparse
import importlib
import sys
import tempfile
import types
import unittest
import re
from pathlib import Path
from unittest.mock import patch


def _load_cli_module():
    rich = types.ModuleType("rich")
    console_module = types.ModuleType("rich.console")
    panel_module = types.ModuleType("rich.panel")
    prompt_module = types.ModuleType("rich.prompt")
    table_module = types.ModuleType("rich.table")
    console_module.Console = type("Console", (), {"print": lambda *args, **kwargs: None})
    panel_module.Panel = type("Panel", (), {"fit": staticmethod(lambda value, **kwargs: value)})
    prompt_module.Prompt = type("Prompt", (), {})
    prompt_module.Confirm = type("Confirm", (), {})
    table_module.Table = type("Table", (), {})
    modules = {
        "rich": rich,
        "rich.console": console_module,
        "rich.panel": panel_module,
        "rich.prompt": prompt_module,
        "rich.table": table_module,
        "psutil": types.ModuleType("psutil"),
    }
    with patch.dict(sys.modules, modules):
        return importlib.import_module("wca")


class CliInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cli = _load_cli_module()

    @staticmethod
    def _args(installer, output, name, mode="static"):
        return argparse.Namespace(
            installer=str(installer), assessment_name=name, output=str(output), mode=mode,
            non_interactive=True, no_gui=True,
        )

    def test_empty_sanitized_assessment_name_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            installer = root / "setup.exe"
            installer.write_bytes(b"MZ")
            with self.assertRaisesRegex(SystemExit, "Assessment name"):
                self.cli.resolve_inputs(self._args(installer, root, "   "))

    def test_noninteractive_full_mode_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            installer = root / "setup.exe"
            installer.write_bytes(b"MZ")
            with self.assertRaisesRegex(SystemExit, "Non-interactive full mode"):
                self.cli.resolve_inputs(self._args(installer, root, "assessment", mode="full"))

    def test_privilege_result_comes_from_privilege_boundary_review(self):
        source = Path("wca.py").read_text(encoding="utf-8")
        assignment = re.compile(
            r'privilege_result\s*=\s*run_module\(\s*reporter,\s*"Privilege Boundary Review"',
            re.MULTILINE,
        )
        self.assertRegex(source, assignment)


if __name__ == "__main__":
    unittest.main()

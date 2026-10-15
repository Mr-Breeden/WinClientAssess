import os
import unittest
from unittest.mock import patch

from utils.powershell import run_powershell


class PowerShellTests(unittest.TestCase):
    def test_windows_powershell_does_not_inherit_pwsh_module_path(self):
        with patch.dict(os.environ, {"PSModulePath": r"C:\PowerShell7\Modules"}, clear=False):
            with patch("utils.powershell.powershell_path", return_value=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"):
                with patch("utils.powershell.run_command", return_value={"returncode": 0, "stdout": "", "stderr": ""}) as command:
                    run_powershell("Get-Date")

        child_env = command.call_args.kwargs["env"]
        self.assertFalse(any(key.lower() == "psmodulepath" for key in child_env))

    def test_pwsh_preserves_module_path(self):
        expected = r"C:\PowerShell7\Modules"
        with patch.dict(os.environ, {"PSModulePath": expected}, clear=False):
            with patch("utils.powershell.powershell_path", return_value=r"C:\Program Files\PowerShell\7\pwsh.exe"):
                with patch("utils.powershell.run_command", return_value={"returncode": 0, "stdout": "", "stderr": ""}) as command:
                    run_powershell("Get-Date")

        child_env = command.call_args.kwargs["env"]
        actual = next(value for key, value in child_env.items() if key.lower() == "psmodulepath")
        self.assertEqual(expected, actual)


if __name__ == "__main__":
    unittest.main()

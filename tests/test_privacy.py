import os
import unittest
from unittest.mock import patch

from utils.component_context import account_for_report


class PrivacyTests(unittest.TestCase):
    def test_current_interactive_user_is_normalized(self):
        with patch.dict(os.environ, {"USERNAME": "Alice"}, clear=False):
            self.assertEqual("CURRENT_USER", account_for_report("Alice"))
            self.assertEqual("CURRENT_USER", account_for_report(r"WORKSTATION\Alice"))
            self.assertEqual(r"NT AUTHORITY\SYSTEM", account_for_report(r"NT AUTHORITY\SYSTEM"))


if __name__ == "__main__":
    unittest.main()

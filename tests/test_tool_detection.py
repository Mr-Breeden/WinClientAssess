import unittest
from utils.tool_detection import TOOLS


class ToolDetectionTests(unittest.TestCase):
    def test_usage_classifications(self):
        self.assertEqual("INTEGRATED", TOOLS["Procmon"][2])
        self.assertEqual("INTEGRATED_FALLBACK", TOOLS["PipeList"][2])
        self.assertEqual("MANUAL", TOOLS["Sigcheck"][2])
        self.assertEqual("MANUAL_GUIDED", TOOLS["dotnet-trace"][2])


if __name__ == "__main__":
    unittest.main()

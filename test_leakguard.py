import tempfile
import unittest
from pathlib import Path
import leakguard

class LeakGuardTests(unittest.TestCase):
    def test_entropy(self):
        self.assertGreater(leakguard.entropy("a8F!92LmQx7Zp3K"), leakguard.entropy("aaaaaaaaaaaaaaa"))

    def test_model_probability(self):
        model = leakguard.train_model()
        self.assertGreater(model.predict_proba(leakguard.features("a8F!92LmQx7Zp3K")),
                           model.predict_proba(leakguard.features("hello world")))

    def test_secret_detection(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "config.py"
            p.write_text('API_KEY = "AKIA1234567890ABCDEF"\n', encoding="utf-8")
            report = leakguard.scan(Path(d))
            self.assertGreaterEqual(report["finding_count"], 1)
            self.assertEqual(report["findings"][0]["type"], "AWS_ACCESS_KEY")

if __name__ == "__main__":
    unittest.main()

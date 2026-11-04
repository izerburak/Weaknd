import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from weaknd import report
from weaknd.attack import AttackResult


class ReportRedactionTests(unittest.TestCase):
    def test_safe_data_removes_nested_secret_fields(self):
        value = {
            "host": "192.0.2.1",
            "attack": AttackResult(
                host="192.0.2.1", found=True, user="admin",
                password="non-default-secret", via="derive",
            ),
            "raw": {"shadow": "root:hash", "identity": "uid=0(root)"},
            "derived": ["candidate-secret"],
        }

        safe = report.safe_data(value)

        self.assertNotIn("password", safe["attack"])
        self.assertNotIn("shadow", safe["raw"])
        self.assertNotIn("derived", safe)
        self.assertEqual(safe["attack"]["user"], "admin")
        self.assertEqual(safe["raw"]["identity"], "uid=0(root)")

    def test_save_never_persists_password_field_or_value(self):
        with tempfile.TemporaryDirectory() as directory:
            result = AttackResult(
                host="192.0.2.1", found=True, user="admin",
                password="non-default-secret", via="default",
            )
            with mock.patch.object(report, "ARTIFACTS", Path(directory)):
                path = report.save("attack", result.host, result)
            text = path.read_text()
            parsed = json.loads(text)

        self.assertNotIn("password", parsed)
        self.assertNotIn("non-default-secret", text)
        self.assertTrue(parsed["found"])


if __name__ == "__main__":
    unittest.main()

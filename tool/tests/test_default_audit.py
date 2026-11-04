import dataclasses
import subprocess
import unittest
from unittest.mock import patch

from weaknd import default_audit
from weaknd.discovery import NetworkContext
from weaknd.ssh_probe import SSHInfo


class DefaultAuditTests(unittest.TestCase):
    def test_minimal_profile_is_exactly_three_requested_pairs(self):
        credentials = default_audit.load_profile("minimal")
        self.assertEqual([credential.label for credential in credentials],
                         ["admin/admin", "root/root", "1234/1234"])

    @patch("weaknd.default_audit.ssh.have_sshpass", return_value=True)
    @patch("weaknd.default_audit.ssh.execute")
    @patch("weaknd.default_audit.ssh_probe.run")
    @patch("weaknd.default_audit.validate_connected_lan_target")
    def test_success_stops_and_result_contains_no_password_field(
            self, scope, probe, execute, _have_sshpass):
        scope.return_value = NetworkContext("lan", "wlan0", "192.168.1.10", 24,
                                            "192.168.1.0/24", "192.168.1.1")
        probe.return_value = SSHInfo("192.168.1.1", banner="SSH-2.0-dropbear",
                                     auth_methods=["password"], reachable=True)
        execute.return_value = subprocess.CompletedProcess(
            [], 0, stdout="WEAKND_OK\nuid=0(root) gid=0(root)\n", stderr="")

        result = default_audit.run("192.168.1.1", profile="minimal", delay=0.5)

        self.assertTrue(result.found)
        self.assertTrue(result.is_root)
        self.assertEqual(len(result.attempts), 1)
        self.assertNotIn("password", dataclasses.asdict(result))
        self.assertNotIn("password", result.attempts[0].__dict__)


if __name__ == "__main__":
    unittest.main()


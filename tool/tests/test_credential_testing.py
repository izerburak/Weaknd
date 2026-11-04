import json
import unittest
from unittest import mock

from weaknd import credential_testing, report


class CredentialTestingTests(unittest.TestCase):
    def test_options_expose_review_labels_but_no_password_fields(self):
        result = credential_testing.options({})

        self.assertEqual({item["name"] for item in result["protocols"]},
                         {"ssh", "telnet"})
        self.assertEqual(result["max_default_attempts"], 3)
        self.assertTrue(result["default_credentials"])
        self.assertTrue(all("password" not in item for item in result["default_credentials"]))

    def test_recon_offers_confirmed_services_and_quick_recon_candidates(self):
        recon = {"ports": [
            {"port": 2222, "protocol": "tcp", "state": "open", "service": "ssh",
             "product": "Dropbear sshd", "service_method": "probed", "service_confidence": 10},
            {"port": 23, "protocol": "tcp", "state": "open", "service": "telnet",
             "product": None, "service_method": "table", "service_confidence": 3},
            {"port": 69, "protocol": "tcp", "state": "open", "service": "tftp",
             "product": "Example TFTP", "service_method": "probed", "service_confidence": 10},
        ]}

        services = credential_testing.discovered_services(recon)

        self.assertEqual([(item["protocol"], item["port"]) for item in services],
                         [("ssh", 2222), ("telnet", 23)])
        self.assertTrue(services[0]["confirmed"])
        self.assertFalse(services[1]["confirmed"])

    @mock.patch.object(credential_testing, "runtime_available", return_value=True)
    @mock.patch.object(credential_testing, "_runner_attempt")
    def test_single_result_never_contains_supplied_password(self, attempt, _runtime):
        attempt.return_value = {
            "status": "authentication_failed",
            "evidence": "The SSH service rejected the supplied credential.",
            "duration_seconds": 0.2,
        }

        result = credential_testing.run(
            "192.0.2.1", "ssh", 22, "single", username="admin",
            password="private-test-value", authorized=True, job_id="single-test",
        )
        serialized = json.dumps(report.safe_data(result))

        self.assertEqual(result.attempted_credentials, 1)
        self.assertEqual(result.final_result, "Authentication Failed")
        self.assertNotIn("password", serialized.lower())
        self.assertNotIn("private-test-value", serialized)
        self.assertNotIn("private-test-value", result.finding.evidence)

    @mock.patch.object(credential_testing, "runtime_available", return_value=True)
    @mock.patch.object(credential_testing, "_runner_attempt")
    def test_default_check_is_bounded_and_stops_on_success(self, attempt, _runtime):
        attempt.return_value = {
            "status": "authentication_successful",
            "evidence": "Authentication accepted; no command executed.",
            "duration_seconds": 0.1,
        }
        selected = [item["id"] for item in credential_testing.default_options()[:4]]

        result = credential_testing.run(
            "192.0.2.1", "telnet", 23, "defaults",
            selected_default_ids=selected, authorized=True, job_id="defaults-test",
        )

        self.assertEqual(attempt.call_count, 1)
        self.assertEqual(result.attempted_credentials, 1)
        self.assertTrue(result.stopped_on_success)
        self.assertEqual(result.finding.validation_status, "VALIDATED")
        self.assertNotIn(selected[0], json.dumps(report.safe_data(result)))

    def test_runner_transports_password_on_stdin_not_argv(self):
        captured = {}

        class FakeProcess:
            def communicate(self, input=None, timeout=None):
                captured["input"] = input
                return ('WEAKND_CREDENTIAL_JSON={"status":"authentication_failed",'
                        '"evidence":"rejected","duration_seconds":0.1}\n', "")

            def poll(self):
                return 0

        with mock.patch.object(credential_testing.subprocess, "Popen",
                               return_value=FakeProcess()) as popen:
            result = credential_testing._runner_attempt(
                "192.0.2.1", "ssh", 22, "admin", "stdin-only-secret", "stdin-test")

        command = popen.call_args.args[0]
        self.assertNotIn("stdin-only-secret", " ".join(command))
        self.assertIn("stdin-only-secret", captured["input"])
        self.assertNotIn("stdin-only-secret", json.dumps(result))

    @mock.patch.object(credential_testing, "runtime_available", return_value=True)
    def test_default_check_rejects_more_than_three_selections(self, _runtime):
        selected = ["one", "two", "three", "four"]

        with self.assertRaisesRegex(ValueError, "between 1 and 3"):
            credential_testing.run(
                "192.0.2.1", "ssh", 22, "defaults",
                selected_default_ids=selected, authorized=True,
            )

    def test_cancel_terminates_the_active_attempt(self):
        process = mock.Mock()
        process.poll.return_value = None
        job_id = "cancel-test"
        with credential_testing._jobs_lock:
            credential_testing._active_jobs.add(job_id)
            credential_testing._jobs[job_id] = process
        try:
            self.assertTrue(credential_testing.cancel(job_id))
            process.terminate.assert_called_once_with()
        finally:
            with credential_testing._jobs_lock:
                credential_testing._active_jobs.discard(job_id)
                credential_testing._jobs.pop(job_id, None)
                credential_testing._cancelled.discard(job_id)


if __name__ == "__main__":
    unittest.main()

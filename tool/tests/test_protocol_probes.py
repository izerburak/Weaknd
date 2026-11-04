import unittest
from unittest.mock import patch

from weaknd import cwmp_probe, telnet_probe


class ProtocolProbeTests(unittest.TestCase):
    @patch("weaknd.cwmp_probe._request")
    def test_cwmp_marks_unauthenticated_2xx_for_review(self, request):
        request.side_effect = [
            cwmp_probe.HTTPObservation("HEAD", 200, "OK", "gSOAP/2.7"),
            cwmp_probe.HTTPObservation("GET", 200, "OK", "gSOAP/2.7"),
            cwmp_probe.HTTPObservation("OPTIONS", 200, "OK", "gSOAP/2.7"),
        ]
        result = cwmp_probe.run("192.0.2.1")
        self.assertTrue(result.reachable)
        self.assertTrue(result.unauthenticated_2xx)
        self.assertEqual(result.verdict, "exposed-review")

    @patch("weaknd.cwmp_probe._request")
    def test_cwmp_records_auth_challenge(self, request):
        request.side_effect = [
            cwmp_probe.HTTPObservation("HEAD", 401, "Unauthorized",
                                       www_authenticate="Digest realm=cpe"),
            cwmp_probe.HTTPObservation("GET", 401, "Unauthorized",
                                       www_authenticate="Digest realm=cpe"),
            cwmp_probe.HTTPObservation("OPTIONS", 401, "Unauthorized",
                                       www_authenticate="Digest realm=cpe"),
        ]
        result = cwmp_probe.run("192.0.2.1")
        self.assertEqual(result.verdict, "protected")
        self.assertEqual(result.auth_schemes, ["Digest"])

    @patch("weaknd.telnet_probe.socket.create_connection")
    def test_telnet_reads_banner_without_credentials(self, connect):
        class FakeSocket:
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def settimeout(self, _): pass
            def recv(self, _): return b"Sagemcom CPE\r\nlogin: "
        connect.return_value = FakeSocket()
        result = telnet_probe.run("192.0.2.1")
        self.assertTrue(result.reachable)
        self.assertTrue(result.login_prompt)
        self.assertIn("Sagemcom", result.banner)


if __name__ == "__main__":
    unittest.main()


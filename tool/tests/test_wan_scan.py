from pathlib import Path
import unittest
from unittest import mock

from weaknd.wan_scan import (PortObservation, _command, _parse_xml,
                             completion_status, derive_findings, infer_identity)


FIXTURE = Path(__file__).parent / "fixtures" / "nmap_10_open_ports.xml"


class WanScanXmlTests(unittest.TestCase):
    def test_saved_fixture_preserves_all_open_ports_and_service_certainty(self):
        ports = _parse_xml(FIXTURE.read_text())

        self.assertEqual(len(ports), 10)
        self.assertEqual(
            {port.port for port in ports},
            {21, 22, 23, 53, 80, 443, 8080, 8443, 7547, 2323},
        )
        ftp = next(port for port in ports if port.port == 21)
        self.assertEqual(ftp.service, "ftp")
        self.assertEqual(ftp.service_method, "table")
        self.assertEqual(ftp.service_confidence, 3)

    def test_findings_require_service_evidence_not_well_known_port_numbers(self):
        findings = derive_findings([
            PortObservation(23, "tcp", "open", "telnet", "BusyBox telnetd",
                            service_method="probed", service_confidence=10),
            PortObservation(2323, "tcp", "open", "3d-nfsd",
                            service_method="table", service_confidence=3),
            PortObservation(7547, "tcp", "open", "tcpwrapped",
                            service_method="probed", service_confidence=8),
        ])

        self.assertEqual([item.title for item in findings], ["Insecure Remote Management"])
        self.assertIn("23/tcp", findings[0].evidence)

    def test_identity_is_derived_only_from_public_fingerprint_evidence(self):
        ports = [
            PortObservation(
                80, "tcp", "open", "http", "Zyxel Web-Based Configurator",
                scripts={
                    "http-title": "Welcome to the Web-Based Configurator",
                    "http-headers": "Model: EX3301-T0\nFirmware Version: V5.50(ABVY.4.3)b1_Y0",
                },
            ),
        ]

        manufacturer, model, firmware, evidence = infer_identity(ports)

        self.assertEqual(manufacturer, "Zyxel")
        self.assertEqual(model, "EX3301-T0")
        self.assertEqual(firmware, "V5.50(ABVY.4.3)b1_Y0")
        self.assertEqual(len(evidence), 3)

    def test_user_identity_wins_and_generic_service_version_is_not_firmware(self):
        ports = [PortObservation(80, "tcp", "open", "http", "nginx", "1.24.0")]

        manufacturer, model, firmware, evidence = infer_identity(
            ports, "Zyxel", "EX3301-T0")

        self.assertEqual((manufacturer, model, firmware),
                         ("Zyxel", "EX3301-T0", None))
        self.assertEqual(evidence, [])

    def test_quick_recon_is_the_minimal_exact_tcp_command(self):
        quick, quick_timeout = _command("192.0.2.1", "quick", None)

        self.assertEqual(quick, [
            "nmap", "-Pn", "-n", "-sT", "-p",
            "21,22,23,53,80,443,8080,8443,7547,2323",
            "--reason", "--max-retries", "2", "-oX", "-", "192.0.2.1",
        ])
        self.assertEqual(quick_timeout, 45)

    def test_host_budget_exhaustion_is_not_reported_as_completed_empty_scan(self):
        self.assertEqual(completion_status("quick", 150.2, []), "completed")
        self.assertEqual(completion_status("quick", 40.0, []), "completed")
        self.assertEqual(
            completion_status("quick", 150.2,
                              [PortObservation(22, "tcp", "open", "ssh")]),
            "completed",
        )


class PentestCandidateTests(unittest.TestCase):
    def test_safe_checks_can_validate_table_candidates_without_creating_findings(self):
        from weaknd.pentest import availability

        ports = _parse_xml(FIXTURE.read_text())
        by_port = {port.port: port for port in ports}
        by_port[23].service_method = "probed"
        by_port[23].service_confidence = 10
        by_port[23].product = "BusyBox telnetd"
        by_port[80].product = None
        by_port[80].service_method = "table"
        by_port[80].service_confidence = 3
        by_port[2323].service = "3d-nfsd"
        by_port[7547].service = "tcpwrapped"
        by_port[7547].service_method = "probed"
        by_port[7547].service_confidence = 8
        result = availability("203.0.113.10", {
            "ports": [port.__dict__ for port in ports],
        })

        self.assertEqual(result["engines"]["nmap"]["checks"], 8)
        self.assertEqual(result["engines"]["nuclei"]["checks"], 1)
        nuclei = next(item for item in result["checks"] if item["engine"] == "nuclei")
        self.assertEqual(
            {item["url"] for item in nuclei["parameters"]["targets"]},
            {
                "http://203.0.113.10:80",
                "https://203.0.113.10:443",
                "http://203.0.113.10:8080",
                "https://203.0.113.10:8443",
            },
        )
        baseline = [(item["title"], item["port"])
                    for item in result["baseline_findings"]]
        self.assertEqual(
            [port for title, port in baseline if title == "Open Port / Observation"],
            sorted(by_port),
        )
        self.assertIn(("WAN-Accessible Telnet", 23), baseline)

    def test_pentest_uses_identity_discovered_by_recon(self):
        from weaknd import pentest

        recon = {"manufacturer": "Zyxel", "model": "EX3301-T0", "ports": []}
        with mock.patch.object(pentest, "_routersploit_checks", return_value=[]) as checks:
            result = pentest.availability("192.0.2.1", recon)

        checks.assert_called_once_with(recon, "Zyxel", "EX3301-T0")
        self.assertIn("detected device identity", result["engines"]["routersploit"]["note"])

    def test_routersploit_does_not_treat_vendor_as_model_match(self):
        from weaknd import pentest

        catalog = [{
            "module": "exploits.routers.zyxel.old_info_disclosure",
            "name": "Old Zyxel check", "description": "test", "references": [],
            "devices": ["Zyxel P660HN-T"], "protocol": "http", "port": 80,
            "vendor": "zyxel",
        }]
        recon = {"ports": [{
            "port": 80, "protocol": "tcp", "state": "open", "service": "http",
            "product": "Zyxel Web-Based Configurator", "service_method": "probed",
            "service_confidence": 10,
        }]}
        with mock.patch.object(pentest, "_routersploit_catalog", return_value=catalog):
            checks = pentest._routersploit_checks(recon, "Zyxel", "EX3301-T0")

        self.assertEqual(checks, [])


class NucleiBatchTests(unittest.TestCase):
    def setUp(self):
        from weaknd.pentest import ApplicableCheck

        self.targets = [
            {"url": "http://203.0.113.10:80", "port": 80,
             "protocol": "tcp", "service": "http"},
            {"url": "https://203.0.113.10:443", "port": 443,
             "protocol": "tcp", "service": "https"},
        ]
        self.templates = [
            Path("http/technologies/tech-detect.yaml"),
            Path("http/misconfiguration/server-status.yaml"),
            Path("ssl/self-signed-ssl.yaml"),
            Path("ssl/expired-ssl.yaml"),
            Path("ssl/deprecated-tls.yaml"),
        ]
        self.check = ApplicableCheck(
            check_id="nuclei:automatic-web", engine="nuclei", name="Nuclei",
            description="test", parameters={"targets": self.targets},
        )

    def test_batches_split_each_target_and_keep_tls_on_https_only(self):
        from weaknd.pentest import _nuclei_batches

        batches = _nuclei_batches(self.targets, self.templates)

        self.assertEqual(
            [(family, item["url"], [path.parts[0] for path in templates])
             for family, item, templates in batches],
            [
                ("http", "http://203.0.113.10:80", ["http", "http"]),
                ("http", "https://203.0.113.10:443", ["http", "http"]),
                ("tls", "https://203.0.113.10:443", ["ssl"]),
                ("tls", "https://203.0.113.10:443", ["ssl"]),
                ("tls", "https://203.0.113.10:443", ["ssl"]),
            ],
        )

    def test_runner_executes_batches_sequentially(self):
        from weaknd import pentest

        completed = ("", "", 0, 0.25, False)
        with mock.patch.object(pentest.shutil, "which", return_value="/usr/bin/nuclei"), \
                mock.patch.object(pentest, "_nuclei_template_set", return_value=self.templates), \
                mock.patch.object(pentest, "_verify_http_target", return_value=(True, "verified")), \
                mock.patch.object(pentest, "_run_process", side_effect=[completed] * 5) as process:
            findings, execution = pentest._run_nuclei(
                "203.0.113.10", self.check, None, "batch-test")

        self.assertEqual(findings, [])
        self.assertEqual(execution.status, "completed")
        self.assertEqual(execution.checks_run, 5)
        self.assertEqual(process.call_count, 5)
        for index, call in enumerate(process.call_args_list):
            command = call.args[0]
            self.assertEqual(command.count("-u"), 1)
            self.assertIn("45s" if index < 2 else "50s", command)
            self.assertEqual(call.args[1], 55 if index < 2 else 60)

    def test_timeout_keeps_going_and_reports_partial_status(self):
        from weaknd import pentest

        outcomes = [
            ("", "budget reached", 1, 45.0, False),
            ("", "", 0, 0.2, False),
            ("", "", 0, 0.2, False),
            ("", "", 0, 0.2, False),
            ("", "", 0, 0.2, False),
        ]
        with mock.patch.object(pentest.shutil, "which", return_value="/usr/bin/nuclei"), \
                mock.patch.object(pentest, "_nuclei_template_set", return_value=self.templates), \
                mock.patch.object(pentest, "_verify_http_target", return_value=(True, "verified")), \
                mock.patch.object(pentest, "_run_process", side_effect=outcomes) as process:
            _, execution = pentest._run_nuclei(
                "203.0.113.10", self.check, None, "timeout-test")

        self.assertEqual(process.call_count, 5)
        self.assertEqual(execution.status, "incomplete")
        self.assertEqual(execution.checks_run, 5)
        self.assertIn("partial findings retained", execution.note)


if __name__ == "__main__":
    unittest.main()

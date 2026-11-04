import unittest

from weaknd.discovery import (HostInfo, NetworkContext, PortInfo, WifiNetwork,
                              COMMON_UDP_PORTS, _merge_hosts, _port_arguments,
                              _split_nmcli, _udp_arguments,
                              enrich_identities, parse_nmap_xml)


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.20.1" addrtype="ipv4"/>
    <address addr="74:12:13:21:4B:4C" addrtype="mac" vendor="Example Networks"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="Dropbear sshd" version="2020.81"/>
      </port>
      <port protocol="tcp" portid="23"><state state="closed"/></port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="embedded web server"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

UDP_XML = """<?xml version="1.0"?>
<nmaprun><host><status state="up"/>
  <address addr="192.168.20.1" addrtype="ipv4"/>
  <ports>
    <port protocol="udp" portid="53"><state state="open"/>
      <service name="domain" product="dnsmasq"/></port>
    <port protocol="udp" portid="1900"><state state="open|filtered"/>
      <service name="upnp"/></port>
  </ports>
</host></nmaprun>
"""


class DiscoveryParsingTests(unittest.TestCase):
    def test_parse_open_ports_and_identity(self):
        hosts = parse_nmap_xml(NMAP_XML)
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].address, "192.168.20.1")
        self.assertEqual(hosts[0].vendor, "Example Networks")
        self.assertEqual([port.port for port in hosts[0].ports], [22, 80])
        self.assertEqual(hosts[0].ports[0].product, "Dropbear sshd")

    def test_merge_preserves_and_updates_ports(self):
        base = [HostInfo("192.168.20.1", ports=[PortInfo(22, service="ssh")])]
        update = [HostInfo("192.168.20.1", ports=[PortInfo(80, service="http")])]
        merged = _merge_hosts(base, update)
        self.assertEqual([port.port for port in merged[0].ports], [22, 80])

    def test_profiles_build_expected_nmap_arguments(self):
        self.assertIn("--top-ports", _port_arguments("top", True))
        self.assertIn("-sV", _port_arguments("top", True))
        self.assertIn("-p-", _port_arguments("all", False))
        self.assertNotIn("-sV", _port_arguments("all", False))

    def test_common_udp_profile_is_bounded_and_service_aware(self):
        arguments = _udp_arguments("common", True)
        self.assertIn("-sU", arguments)
        self.assertIn("-sV", arguments)
        ports = arguments[arguments.index("-p") + 1]
        self.assertEqual({int(port) for port in ports.split(",")},
                         set(COMMON_UDP_PORTS))
        self.assertEqual(_udp_arguments("none", True), [])

    def test_udp_parser_retains_only_confirmed_open_ports(self):
        hosts = parse_nmap_xml(UDP_XML)
        self.assertEqual([(port.port, port.protocol) for port in hosts[0].ports],
                         [(53, "udp")])

    def test_nmcli_escaped_bssid_is_parsed(self):
        line = r"*:TMNL:80\:69\:1A\:87\:41\:D9:85:48:WPA2"
        self.assertEqual(
            _split_nmcli(line),
            ["*", "TMNL", "80:69:1A:87:41:D9", "85", "48", "WPA2"],
        )

    def test_identity_correlates_host_mac_with_ssid_bssid_family(self):
        context = NetworkContext("lan", "wlan0", "192.168.20.10", 24,
                                 "192.168.20.0/24", "192.168.20.1", "TMNL", None)
        host = HostInfo("192.168.20.186", mac="80:69:1A:87:41:D7",
                        vendor="Belkin International")
        wifi = [WifiNetwork("TMNL", "80:69:1A:87:41:D9", active=True)]
        enrich_identities([host], wifi, context)
        self.assertEqual(host.matched_ssids, ["TMNL"])
        self.assertEqual(host.role, "Wi-Fi AP/bridge candidate")
        self.assertEqual(host.identity_confidence, "probable")


if __name__ == "__main__":
    unittest.main()


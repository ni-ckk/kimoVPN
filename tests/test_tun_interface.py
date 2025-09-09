"""
Test suite for TUN interface functionality.
"""

import unittest
import time
from unittest.mock import MagicMock, patch
from ipaddress import IPv4Network

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.common.ip_packet import IPPacketHandler, PacketFilter
from src.server.ip_pool import IPPool, IPPoolManager
from src.server.packet_router import PacketRouter, ClientHandler


class TestIPPacketHandler(unittest.TestCase):
    """Test IP packet handling."""
    
    def setUp(self):
        """Set up test environment."""
        self.handler = IPPacketHandler("10.8.0.0/24")
    
    def test_parse_valid_packet(self):
        """Test parsing valid packet."""
        # create a simple ip packet
        from scapy.all import IP, TCP, Raw
        packet = IP(src="10.8.0.2", dst="8.8.8.8") / TCP() / Raw(b"test data")
        raw_data = bytes(packet)
        
        parsed = self.handler.parse_packet(raw_data)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.src, "10.8.0.2")
        self.assertEqual(parsed.dst, "8.8.8.8")
    
    def test_parse_invalid_packet(self):
        """Test parsing invalid packet."""
        invalid_data = b"not a valid packet"
        parsed = self.handler.parse_packet(invalid_data)
        self.assertIsNone(parsed)
    
    def test_build_packet(self):
        """Test building packet."""
        packet_bytes = self.handler.build_packet(
            src="10.8.0.2",
            dst="8.8.8.8",
            payload=b"test payload",
            proto="tcp"
        )
        
        self.assertIsInstance(packet_bytes, bytes)
        self.assertGreater(len(packet_bytes), 0)
        
        # verify we can parse it back
        parsed = self.handler.parse_packet(packet_bytes)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.src, "10.8.0.2")
        self.assertEqual(parsed.dst, "8.8.8.8")
    
    def test_is_valid_destination(self):
        """Test destination validation."""
        from scapy.all import IP
        
        # valid public ip
        packet = IP(src="10.8.0.2", dst="8.8.8.8")
        self.assertTrue(self.handler.is_valid_destination(packet))
        
        # valid vpn network ip
        packet = IP(src="10.8.0.2", dst="10.8.0.3")
        self.assertTrue(self.handler.is_valid_destination(packet))
        
        # invalid private ip (not in vpn network)
        packet = IP(src="10.8.0.2", dst="192.168.1.1")
        self.assertFalse(self.handler.is_valid_destination(packet))
        
        # invalid multicast
        packet = IP(src="10.8.0.2", dst="224.0.0.1")
        self.assertFalse(self.handler.is_valid_destination(packet))
    
    def test_rewrite_addresses(self):
        """Test address rewriting."""
        from scapy.all import IP, TCP
        
        packet = IP(src="10.8.0.2", dst="8.8.8.8") / TCP()
        
        # rewrite source
        modified = self.handler.rewrite_source(packet, "10.8.0.5")
        self.assertEqual(modified.src, "10.8.0.5")
        
        # rewrite destination
        modified = self.handler.rewrite_destination(packet, "1.1.1.1")
        self.assertEqual(modified.dst, "1.1.1.1")


class TestPacketFilter(unittest.TestCase):
    """Test packet filtering."""
    
    def setUp(self):
        """Set up test environment."""
        self.filter = PacketFilter()
    
    def test_default_allow(self):
        """Test default allow with no rules."""
        from scapy.all import IP
        packet = IP(src="10.8.0.2", dst="8.8.8.8")
        self.assertTrue(self.filter.check_packet(packet))
    
    def test_allow_rule(self):
        """Test allow rule."""
        from scapy.all import IP, TCP
        
        # add allow rule for specific destination
        self.filter.add_rule(
            action="allow",
            dst="8.8.8.0/24"
        )
        
        # should allow
        packet = IP(src="10.8.0.2", dst="8.8.8.8") / TCP()
        self.assertTrue(self.filter.check_packet(packet))
        
        # should deny (no matching rule, default deny)
        packet = IP(src="10.8.0.2", dst="1.1.1.1") / TCP()
        self.assertFalse(self.filter.check_packet(packet))
    
    def test_deny_rule(self):
        """Test deny rule."""
        from scapy.all import IP, TCP
        
        # add deny rule for port 22
        self.filter.add_rule(
            action="deny",
            proto="tcp",
            port=22
        )
        
        # add allow all rule
        self.filter.add_rule(action="allow")
        
        # should deny ssh
        packet = IP(src="10.8.0.2", dst="8.8.8.8") / TCP(dport=22)
        self.assertFalse(self.filter.check_packet(packet))
        
        # should allow other ports
        packet = IP(src="10.8.0.2", dst="8.8.8.8") / TCP(dport=80)
        self.assertTrue(self.filter.check_packet(packet))


class TestIPPool(unittest.TestCase):
    """Test IP address pool management."""
    
    def setUp(self):
        """Set up test environment."""
        self.pool = IPPool(
            network="10.8.0.0/24",
            server_ip="10.8.0.1"
        )
    
    def test_assign_ip(self):
        """Test IP assignment."""
        # first assignment
        ip1 = self.pool.assign_ip("user1")
        self.assertIsNotNone(ip1)
        self.assertIn(ip1, ["10.8.0.2", "10.8.0.3", "10.8.0.254"])
        
        # second assignment (different user)
        ip2 = self.pool.assign_ip("user2")
        self.assertIsNotNone(ip2)
        self.assertNotEqual(ip1, ip2)
        
        # same user should get same ip
        ip1_again = self.pool.assign_ip("user1")
        self.assertEqual(ip1, ip1_again)
    
    def test_release_ip(self):
        """Test IP release."""
        # assign ip
        ip = self.pool.assign_ip("user1")
        self.assertIsNotNone(ip)
        
        # release ip
        success = self.pool.release_ip("user1")
        self.assertTrue(success)
        
        # ip should be available again
        ip2 = self.pool.assign_ip("user2")
        self.assertEqual(ip, ip2)
    
    def test_pool_exhaustion(self):
        """Test pool exhaustion."""
        # assign all available ips (253 for /24 minus server)
        users = []
        for i in range(253):
            user = f"user{i}"
            users.append(user)
            ip = self.pool.assign_ip(user)
            self.assertIsNotNone(ip)
        
        # pool should be exhausted
        ip = self.pool.assign_ip("extra_user")
        self.assertIsNone(ip)
        
        # release one and try again
        self.pool.release_ip(users[0])
        ip = self.pool.assign_ip("extra_user")
        self.assertIsNotNone(ip)
    
    def test_get_mappings(self):
        """Test getting IP mappings."""
        # assign some ips
        self.pool.assign_ip("user1")
        self.pool.assign_ip("user2")
        
        # get by user
        ip = self.pool.get_ip_by_user("user1")
        self.assertIsNotNone(ip)
        
        # get by ip
        user = self.pool.get_user_by_ip(ip)
        self.assertEqual(user, "user1")
        
        # get all
        assignments = self.pool.get_all_assignments()
        self.assertEqual(len(assignments), 2)
        self.assertIn("user1", assignments)
        self.assertIn("user2", assignments)
    
    def test_pool_status(self):
        """Test pool status."""
        # assign some ips
        self.pool.assign_ip("user1")
        self.pool.assign_ip("user2")
        
        status = self.pool.get_pool_status()
        
        self.assertEqual(status["network"], "10.8.0.0/24")
        self.assertEqual(status["server_ip"], "10.8.0.1")
        self.assertEqual(status["assigned"], 2)
        self.assertEqual(status["available"], 251)  # 253 - 2


class TestPacketRouter(unittest.TestCase):
    """Test packet routing."""
    
    def setUp(self):
        """Set up test environment."""
        self.ip_pool = IPPool("10.8.0.0/24", "10.8.0.1")
        self.router = PacketRouter(self.ip_pool, tun_interface=None)
    
    def test_register_client(self):
        """Test client registration."""
        mock_handler = MagicMock()
        
        self.router.register_client("10.8.0.2", mock_handler)
        self.assertIn("10.8.0.2", self.router.clients)
        
        self.router.unregister_client("10.8.0.2")
        self.assertNotIn("10.8.0.2", self.router.clients)
    
    def test_route_from_client(self):
        """Test routing from client."""
        from scapy.all import IP, TCP, Raw
        
        # create mock tun interface
        mock_tun = MagicMock()
        mock_tun.running = True
        self.router.tun_interface = mock_tun
        
        # create packet
        packet = IP(src="10.8.0.2", dst="8.8.8.8") / TCP() / Raw(b"test")
        packet_data = bytes(packet)
        
        # route packet
        self.router.route_from_client("10.8.0.2", packet_data)
        
        # verify tun interface received packet
        mock_tun.write_packet.assert_called_once_with(packet_data)
    
    def test_route_to_client(self):
        """Test routing to client."""
        from scapy.all import IP, TCP, Raw
        
        # register mock client
        mock_handler = MagicMock()
        self.router.register_client("10.8.0.2", mock_handler)
        
        # create packet for client
        packet = IP(src="8.8.8.8", dst="10.8.0.2") / TCP() / Raw(b"response")
        packet_data = bytes(packet)
        
        # route packet
        self.router.route_to_client(packet_data)
        
        # verify client received packet
        mock_handler.send_packet.assert_called_once_with(packet_data)
    
    def test_packet_filtering(self):
        """Test packet filtering in router."""
        from scapy.all import IP, TCP
        
        # add filter rule to block port 22
        self.router.add_filter_rule(
            action="deny",
            proto="tcp",
            port=22
        )
        
        # create mock tun
        mock_tun = MagicMock()
        mock_tun.running = True
        self.router.tun_interface = mock_tun
        
        # try to route ssh packet
        packet = IP(src="10.8.0.2", dst="8.8.8.8") / TCP(dport=22)
        packet_data = bytes(packet)
        
        self.router.route_from_client("10.8.0.2", packet_data)
        
        # packet should be filtered (not forwarded)
        mock_tun.write_packet.assert_not_called()
        
        # try http packet
        packet = IP(src="10.8.0.2", dst="8.8.8.8") / TCP(dport=80)
        packet_data = bytes(packet)
        
        self.router.route_from_client("10.8.0.2", packet_data)
        
        # packet should be forwarded
        mock_tun.write_packet.assert_called_once()
    
    def test_statistics(self):
        """Test routing statistics."""
        from scapy.all import IP, TCP, Raw
        
        # create mock tun
        mock_tun = MagicMock()
        mock_tun.running = True
        self.router.tun_interface = mock_tun
        
        # route some packets
        packet = IP(src="10.8.0.2", dst="8.8.8.8") / TCP() / Raw(b"test" * 100)
        packet_data = bytes(packet)
        
        for _ in range(5):
            self.router.route_from_client("10.8.0.2", packet_data)
        
        # check stats
        stats = self.router.get_stats("10.8.0.2")
        self.assertEqual(stats["packets_out"], 5)
        self.assertGreater(stats["bytes_out"], 0)
        self.assertIsNotNone(stats["last_activity"])


class TestTunInterface(unittest.TestCase):
    """Test TUN interface (mock implementation)."""
    
    def test_mock_interface_windows(self):
        """Test mock Windows TUN interface."""
        from src.client.tun_interface import MockWindowsTunInterface
        
        tun = MockWindowsTunInterface(
            ip_address="10.8.0.2",
            gateway="10.8.0.1"
        )
        
        # test lifecycle
        self.assertTrue(tun.create())
        self.assertTrue(tun.start())
        self.assertTrue(tun.running)
        
        # test packet write
        tun.write_packet(b"test packet")
        
        # test stats
        stats = tun.get_stats()
        self.assertEqual(stats["ip_address"], "10.8.0.2")
        self.assertEqual(stats["gateway"], "10.8.0.1")
        self.assertTrue(stats["mock"])
        
        # test stop
        tun.stop()
        self.assertFalse(tun.running)
        
        tun.destroy()
    
    def test_mock_interface_linux(self):
        """Test mock Linux TUN interface."""
        from src.server.tun_interface import MockTunInterface
        
        tun = MockTunInterface(
            ip_address="10.8.0.1",
            netmask="255.255.255.0"
        )
        
        # test lifecycle
        self.assertTrue(tun.create())
        self.assertTrue(tun.start())
        self.assertTrue(tun.running)
        
        # test packet callback
        received_packets = []
        tun.on_packet_received = lambda data: received_packets.append(data)
        
        # write packet (mock echoes back)
        tun.write_packet(b"test packet")
        self.assertEqual(len(received_packets), 1)
        self.assertEqual(received_packets[0], b"test packet")
        
        # test stop
        tun.stop()
        self.assertFalse(tun.running)


if __name__ == "__main__":
    unittest.main()
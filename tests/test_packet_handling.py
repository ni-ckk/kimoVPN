#!/usr/bin/env python3
"""
Unit tests for packet handling functionality (Phase 2).

Tests packet structure, encryption, encoding/decoding, and handlers.
"""

import unittest
import time
import base64
from unittest.mock import Mock, patch, MagicMock

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.common.packet import (
    PacketType,
    PacketFlags,
    PacketHeader,
    VPNPacket,
    PacketEncryptor,
    PacketEncoder,
    PacketDecoder,
    PacketFragmenter,
    PacketStats
)
from src.server.packet_handler import PacketHandler, PacketRouter
from src.client.packet_handler import ClientPacketHandler, PacketTester


class TestPacketHeader(unittest.TestCase):
    """Test packet header structure."""
    
    def test_header_creation(self):
        """Test creating packet header."""
        header = PacketHeader(
            version=1,
            packet_type=PacketType.DATA,
            flags=PacketFlags.ENCRYPTED,
            sequence=42,
            timestamp=1234567890,
            length=100
        )
        
        self.assertEqual(header.version, 1)
        self.assertEqual(header.packet_type, PacketType.DATA)
        self.assertEqual(header.flags, PacketFlags.ENCRYPTED)
        self.assertEqual(header.sequence, 42)
        self.assertEqual(header.timestamp, 1234567890)
        self.assertEqual(header.length, 100)
    
    def test_header_pack_unpack(self):
        """Test packing and unpacking header."""
        original = PacketHeader(
            version=2,
            packet_type=PacketType.ECHO_REQUEST,
            flags=PacketFlags.ENCRYPTED | PacketFlags.FRAGMENTED,
            sequence=999,
            timestamp=int(time.time()),
            length=1024
        )
        
        # pack to bytes
        packed = original.pack()
        self.assertEqual(len(packed), PacketHeader.HEADER_SIZE)
        
        # unpack from bytes
        unpacked = PacketHeader.unpack(packed)
        
        self.assertEqual(unpacked.version, original.version)
        self.assertEqual(unpacked.packet_type, original.packet_type)
        self.assertEqual(unpacked.flags, original.flags)
        self.assertEqual(unpacked.sequence, original.sequence)
        self.assertEqual(unpacked.timestamp, original.timestamp)
        self.assertEqual(unpacked.length, original.length)
    
    def test_header_invalid_size(self):
        """Test unpacking with invalid data size."""
        with self.assertRaises(ValueError):
            PacketHeader.unpack(b"too short")


class TestVPNPacket(unittest.TestCase):
    """Test VPN packet structure."""
    
    def test_packet_creation(self):
        """Test creating VPN packet."""
        header = PacketHeader(
            packet_type=PacketType.DATA,
            sequence=1,
            length=10
        )
        payload = b"test data!"
        
        packet = VPNPacket(header=header, payload=payload)
        
        self.assertEqual(packet.header, header)
        self.assertEqual(packet.payload, payload)
    
    def test_packet_to_bytes(self):
        """Test converting packet to bytes."""
        header = PacketHeader(
            packet_type=PacketType.ECHO_REPLY,
            sequence=5,
            length=5
        )
        payload = b"hello"
        
        packet = VPNPacket(header=header, payload=payload)
        data = packet.to_bytes()
        
        # should be header + payload
        self.assertEqual(len(data), PacketHeader.HEADER_SIZE + len(payload))
        
        # first part should be header
        header_bytes = data[:PacketHeader.HEADER_SIZE]
        self.assertEqual(header_bytes, header.pack())
        
        # second part should be payload
        payload_bytes = data[PacketHeader.HEADER_SIZE:]
        self.assertEqual(payload_bytes, payload)
    
    def test_packet_from_bytes(self):
        """Test creating packet from bytes."""
        original_header = PacketHeader(
            packet_type=PacketType.KEEPALIVE,
            sequence=100,
            length=12
        )
        original_payload = b"keepalive123"
        
        # create bytes
        data = original_header.pack() + original_payload
        
        # reconstruct packet
        packet = VPNPacket.from_bytes(data)
        
        self.assertEqual(packet.header.packet_type, original_header.packet_type)
        self.assertEqual(packet.header.sequence, original_header.sequence)
        self.assertEqual(packet.header.length, original_header.length)
        self.assertEqual(packet.payload, original_payload)


class TestPacketEncryptor(unittest.TestCase):
    """Test packet encryption."""
    
    def test_encryptor_initialization(self):
        """Test encryptor initialization."""
        # with provided key
        key = b"x" * 32
        encryptor = PacketEncryptor(shared_key=key)
        self.assertIsNotNone(encryptor.box)
        
        # without key (generates new)
        encryptor = PacketEncryptor()
        self.assertIsNotNone(encryptor.box)
        self.assertEqual(len(encryptor.shared_key), 32)
    
    def test_encrypt_decrypt(self):
        """Test encryption and decryption."""
        encryptor = PacketEncryptor()
        
        # test data
        original_data = b"This is secret data that should be encrypted!"
        
        # encrypt
        encrypted = encryptor.encrypt(original_data)
        self.assertNotEqual(encrypted, original_data)
        self.assertGreater(len(encrypted), len(original_data))  # includes nonce and MAC
        
        # decrypt
        decrypted = encryptor.decrypt(encrypted)
        self.assertEqual(decrypted, original_data)
    
    def test_invalid_key_size(self):
        """Test initialization with invalid key size."""
        with self.assertRaises(ValueError):
            PacketEncryptor(shared_key=b"too short")
    
    def test_decrypt_tampered_data(self):
        """Test decryption of tampered data."""
        encryptor = PacketEncryptor()
        
        # encrypt data
        original_data = b"secret"
        encrypted = encryptor.encrypt(original_data)
        
        # tamper with encrypted data
        tampered = bytearray(encrypted)
        tampered[-1] ^= 0xFF  # flip last byte
        
        # decryption should fail
        with self.assertRaises(Exception):
            encryptor.decrypt(bytes(tampered))


class TestPacketEncoderDecoder(unittest.TestCase):
    """Test packet encoding and decoding."""
    
    def test_encode_decode_basic(self):
        """Test basic encode/decode cycle."""
        encryptor = PacketEncryptor()
        encoder = PacketEncoder(encryptor)
        decoder = PacketDecoder(encryptor)
        
        # encode data
        data = b"test packet data"
        encoded = encoder.encode(data, PacketType.DATA, encrypt=True)
        
        # decode data
        packet_type, decoded_data = decoder.decode(encoded)
        
        self.assertEqual(packet_type, PacketType.DATA)
        self.assertEqual(decoded_data, data)
    
    def test_encode_without_encryption(self):
        """Test encoding without encryption."""
        encoder = PacketEncoder()
        decoder = PacketDecoder()
        
        data = b"unencrypted data"
        encoded = encoder.encode(data, PacketType.CONTROL, encrypt=False)
        
        packet_type, decoded_data = decoder.decode(encoded)
        
        self.assertEqual(packet_type, PacketType.CONTROL)
        self.assertEqual(decoded_data, data)
    
    def test_echo_packets(self):
        """Test echo request/reply packets."""
        encryptor = PacketEncryptor()
        encoder = PacketEncoder(encryptor)
        decoder = PacketDecoder(encryptor)
        
        # create echo request
        echo_data = b"ping"
        echo_request = encoder.create_echo_request(echo_data)
        
        # decode and verify
        packet_type, decoded = decoder.decode(echo_request)
        self.assertEqual(packet_type, PacketType.ECHO_REQUEST)
        self.assertEqual(decoded, echo_data)
        
        # create echo reply
        echo_reply = encoder.create_echo_reply(echo_data)
        
        # decode and verify
        packet_type, decoded = decoder.decode(echo_reply)
        self.assertEqual(packet_type, PacketType.ECHO_REPLY)
        self.assertEqual(decoded, echo_data)
    
    def test_sequence_increment(self):
        """Test sequence number increments."""
        encoder = PacketEncoder()
        
        initial_seq = encoder.sequence
        encoder.encode(b"data1")
        self.assertEqual(encoder.sequence, initial_seq + 1)
        
        encoder.encode(b"data2")
        self.assertEqual(encoder.sequence, initial_seq + 2)


class TestPacketFragmenter(unittest.TestCase):
    """Test packet fragmentation."""
    
    def test_no_fragmentation_needed(self):
        """Test when data fits in single packet."""
        data = b"x" * 100
        fragments = PacketFragmenter.fragment(data, mtu=1400)
        
        # should return empty list (no fragmentation needed)
        self.assertEqual(len(fragments), 0)
    
    def test_fragmentation(self):
        """Test fragmenting large data."""
        # create data larger than MTU
        mtu = 100
        data = b"x" * 500
        
        fragments = PacketFragmenter.fragment(data, mtu=mtu)
        
        # should have multiple fragments
        self.assertGreater(len(fragments), 1)
        
        # reassemble and verify
        reassembled = b""
        for i, (header, chunk) in enumerate(fragments):
            # check fragment flags
            self.assertTrue(header.flags & PacketFlags.FRAGMENTED)
            
            # last fragment should have LAST_FRAGMENT flag
            if i == len(fragments) - 1:
                self.assertTrue(header.flags & PacketFlags.LAST_FRAGMENT)
            else:
                self.assertFalse(header.flags & PacketFlags.LAST_FRAGMENT)
            
            # check sequence
            self.assertEqual(header.sequence, i)
            
            # collect data
            reassembled += chunk
        
        # verify reassembled data matches original
        self.assertEqual(reassembled, data)


class TestPacketStats(unittest.TestCase):
    """Test packet statistics tracking."""
    
    def test_stats_initialization(self):
        """Test stats initialization."""
        stats = PacketStats()
        
        self.assertEqual(stats.packets_sent, 0)
        self.assertEqual(stats.packets_received, 0)
        self.assertEqual(stats.bytes_sent, 0)
        self.assertEqual(stats.bytes_received, 0)
    
    def test_update_stats(self):
        """Test updating statistics."""
        stats = PacketStats()
        
        # update sent
        stats.update_sent(100, encrypted=True)
        self.assertEqual(stats.packets_sent, 1)
        self.assertEqual(stats.bytes_sent, 100)
        self.assertEqual(stats.packets_encrypted, 1)
        self.assertIsNotNone(stats.last_packet_time)
        
        # update received
        stats.update_received(200, decrypted=True)
        self.assertEqual(stats.packets_received, 1)
        self.assertEqual(stats.bytes_received, 200)
        self.assertEqual(stats.packets_decrypted, 1)
    
    def test_stats_to_dict(self):
        """Test converting stats to dictionary."""
        stats = PacketStats()
        stats.update_sent(50)
        stats.update_received(75)
        
        stats_dict = stats.to_dict()
        
        self.assertIn("packets_sent", stats_dict)
        self.assertIn("packets_received", stats_dict)
        self.assertIn("bytes_sent", stats_dict)
        self.assertIn("bytes_received", stats_dict)
        self.assertEqual(stats_dict["packets_sent"], 1)
        self.assertEqual(stats_dict["bytes_sent"], 50)


class TestServerPacketHandler(unittest.TestCase):
    """Test server-side packet handler."""
    
    def test_handler_initialization(self):
        """Test handler initialization."""
        handler = PacketHandler(echo_mode=True)
        
        self.assertTrue(handler.echo_mode)
        self.assertIsNotNone(handler.encryptor)
        self.assertIsNotNone(handler.encoder)
        self.assertIsNotNone(handler.decoder)
    
    def test_echo_mode(self):
        """Test echo mode functionality."""
        handler = PacketHandler(echo_mode=True)
        
        # create test packet
        test_data = b"echo test data"
        encoder = PacketEncoder(handler.encryptor)
        packet = encoder.encode(test_data, PacketType.DATA)
        
        # process packet
        response = handler.process_packet(packet, "test_client")
        
        # should get response
        self.assertIsNotNone(response)
        
        # decode response
        decoder = PacketDecoder(handler.encryptor)
        packet_type, response_data = decoder.decode(response)
        
        # should be same data echoed back
        self.assertEqual(packet_type, PacketType.DATA)
        self.assertEqual(response_data, test_data)
    
    def test_echo_request_response(self):
        """Test echo request/response handling."""
        handler = PacketHandler()
        
        # create echo request
        echo_data = b"ping"
        encoder = PacketEncoder(handler.encryptor)
        echo_request = encoder.create_echo_request(echo_data)
        
        # process
        response = handler.process_packet(echo_request, "client1")
        
        # should get echo reply
        self.assertIsNotNone(response)
        
        # decode and verify
        decoder = PacketDecoder(handler.encryptor)
        packet_type, payload = decoder.decode(response)
        
        self.assertEqual(packet_type, PacketType.ECHO_REPLY)
        self.assertEqual(payload, echo_data)
    
    def test_client_stats_tracking(self):
        """Test per-client statistics."""
        handler = PacketHandler()
        
        # process packets from different clients
        encoder = PacketEncoder(handler.encryptor)
        
        packet1 = encoder.encode(b"data1", PacketType.DATA)
        packet2 = encoder.encode(b"data2", PacketType.DATA)
        
        handler.process_packet(packet1, "client1")
        handler.process_packet(packet2, "client1")
        handler.process_packet(packet1, "client2")
        
        # check stats
        self.assertIn("client1", handler.client_stats)
        self.assertIn("client2", handler.client_stats)
        
        client1_stats = handler.client_stats["client1"]
        self.assertEqual(client1_stats.packets_received, 2)
        
        client2_stats = handler.client_stats["client2"]
        self.assertEqual(client2_stats.packets_received, 1)


class TestClientPacketHandler(unittest.TestCase):
    """Test client-side packet handler."""
    
    def test_initialization(self):
        """Test client handler initialization."""
        send_callback = Mock()
        handler = ClientPacketHandler(send_callback=send_callback)
        
        self.assertEqual(handler.send_callback, send_callback)
        self.assertIsNotNone(handler.encryptor)
    
    def test_send_data(self):
        """Test sending data packets."""
        handler = ClientPacketHandler()
        
        # send data
        test_data = b"client data"
        handler.send_data(test_data, PacketType.DATA)
        
        # check stats
        self.assertEqual(handler.stats.packets_sent, 1)
        self.assertGreater(handler.stats.bytes_sent, 0)
        
        # check queue
        self.assertFalse(handler.outbound_queue.empty())
    
    def test_echo_request_tracking(self):
        """Test echo request tracking."""
        handler = ClientPacketHandler()
        
        # send echo request
        seq = handler.send_echo_request(b"ping")
        
        # should track the request
        self.assertIn(seq, handler.echo_responses)
        self.assertIsInstance(handler.echo_responses[seq], float)
    
    def test_process_echo_reply(self):
        """Test processing echo reply."""
        handler = ClientPacketHandler()
        
        # track a request
        handler.echo_responses[0] = time.time() - 0.1  # 100ms ago
        
        # create echo reply packet
        encoder = PacketEncoder(handler.encryptor)
        echo_reply = encoder.create_echo_reply(b"pong")
        
        # process it
        handler.process_received_packet(echo_reply)
        
        # should have recorded latency
        self.assertEqual(len(handler.echo_latencies), 1)
        self.assertGreater(handler.echo_latencies[0], 0)
    
    @patch('time.sleep')
    def test_packet_tester_echo(self, mock_sleep):
        """Test packet tester echo functionality."""
        handler = ClientPacketHandler()
        tester = PacketTester(handler)
        
        # simulate echo responses
        handler.echo_latencies = [0.010, 0.015, 0.012]  # 10-15ms
        
        # run test
        results = tester.run_echo_test(count=3, payload_size=64, interval=0.1)
        
        # check results
        self.assertEqual(results["count"], 3)
        self.assertEqual(results["payload_size"], 64)
        self.assertEqual(results["sent"], 3)
        self.assertIn("avg_latency_ms", results)
        self.assertIn("min_latency_ms", results)
        self.assertIn("max_latency_ms", results)


class TestPacketRouter(unittest.TestCase):
    """Test packet routing functionality."""
    
    def test_add_remove_client(self):
        """Test adding and removing clients."""
        router = PacketRouter()
        
        # add client
        router.add_client("client1", "10.8.0.2")
        self.assertIn("10.8.0.2", router.routing_table)
        self.assertEqual(router.routing_table["10.8.0.2"], "client1")
        
        # add another
        router.add_client("client2", "10.8.0.3")
        self.assertEqual(len(router.routing_table), 2)
        
        # remove client
        router.remove_client("client1")
        self.assertNotIn("10.8.0.2", router.routing_table)
        self.assertIn("10.8.0.3", router.routing_table)
    
    def test_route_packet(self):
        """Test packet routing."""
        router = PacketRouter()
        
        # setup routing table
        router.add_client("client1", "10.8.0.2")
        router.add_client("client2", "10.8.0.3")
        
        # route to existing client
        dest_client = router.route_packet("10.8.0.2", "10.8.0.3", b"data")
        self.assertEqual(dest_client, "client2")
        
        # route to non-existent client
        dest_client = router.route_packet("10.8.0.2", "10.8.0.99", b"data")
        self.assertIsNone(dest_client)


if __name__ == "__main__":
    unittest.main()
"""
Client-side packet handling and processing.

This module handles packet operations on the client side,
including sending, receiving, and processing data packets.
"""

import time
import threading
from typing import Optional, Dict, Any, Callable
from queue import Queue, Empty
import base64

from src.common.packet import (
    PacketType,
    PacketEncoder,
    PacketDecoder,
    PacketEncryptor,
    VPNPacket,
    PacketStats
)
from src.common.protocol import MessageType, ProtocolMessage
from src.common.logging import get_logger

logger = get_logger(__name__)


class ClientPacketHandler:
    """Handles packet processing on the client side."""
    
    def __init__(
        self,
        encryptor: Optional[PacketEncryptor] = None,
        send_callback: Optional[Callable] = None
    ):
        """
        Initialize client packet handler.
        
        Args:
            encryptor: Packet encryptor for secure communication
            send_callback: Callback function to send messages to server
        """
        self.encryptor = encryptor or PacketEncryptor()
        self.encoder = PacketEncoder(self.encryptor)
        self.decoder = PacketDecoder(self.encryptor)
        self.send_callback = send_callback
        
        # packet queues
        self.outbound_queue = Queue()
        self.inbound_queue = Queue()
        
        # echo testing
        self.echo_responses: Dict[int, float] = {}  # sequence -> timestamp
        self.echo_latencies: list[float] = []
        
        # statistics
        self.stats = PacketStats()
        
        # processing thread
        self.running = False
        self.send_thread = None
        
        logger.info("client packet handler initialized")
    
    def start(self):
        """Start packet processing."""
        if self.running:
            return
        
        self.running = True
        self.send_thread = threading.Thread(
            target=self._send_loop,
            daemon=True
        )
        self.send_thread.start()
        logger.info("client packet handler started")
    
    def stop(self):
        """Stop packet processing."""
        self.running = False
        if self.send_thread:
            self.send_thread.join(timeout=5)
        logger.info("client packet handler stopped")
    
    def send_data(self, data: bytes, packet_type: PacketType = PacketType.DATA):
        """
        Send data packet to server.
        
        Args:
            data: Data to send
            packet_type: Type of packet
        """
        # encode packet
        packet_data = self.encoder.encode(data, packet_type, encrypt=True)
        
        # update stats
        self.stats.update_sent(len(packet_data), encrypted=True)
        
        # queue for sending
        self.outbound_queue.put(packet_data)
        
        logger.debug(
            "packet queued for sending",
            type=packet_type.name,
            size=len(packet_data)
        )
    
    def send_echo_request(self, data: bytes = b"") -> int:
        """
        Send echo request packet and track it.
        
        Args:
            data: Echo payload (default: empty)
            
        Returns:
            Sequence number of echo request
        """
        if not data:
            data = b"echo test " + str(time.time()).encode()
        
        # get current sequence
        sequence = self.encoder.sequence
        
        # track echo request
        self.echo_responses[sequence] = time.time()
        
        # send echo request
        packet_data = self.encoder.create_echo_request(data)
        self.outbound_queue.put(packet_data)
        
        self.stats.update_sent(len(packet_data), encrypted=True)
        
        logger.debug(f"echo request sent, sequence={sequence}")
        
        return sequence
    
    def process_received_packet(self, packet_data: bytes):
        """
        Process packet data received from server.
        
        Args:
            packet_data: Raw packet data
        """
        try:
            # decode packet
            packet_type, payload = self.decoder.decode(packet_data)
            
            # update stats
            self.stats.update_received(len(packet_data), decrypted=True)
            
            logger.debug(
                "packet received",
                type=packet_type.name,
                size=len(packet_data)
            )
            
            # handle based on type
            if packet_type == PacketType.ECHO_REPLY:
                self._handle_echo_reply(payload)
            elif packet_type == PacketType.DATA:
                self._handle_data_packet(payload)
            elif packet_type == PacketType.KEEPALIVE:
                logger.debug("keepalive packet received")
            else:
                logger.warning(f"unhandled packet type: {packet_type}")
            
        except Exception as e:
            logger.error(f"failed to process packet: {e}")
            self.stats.decryption_errors += 1
    
    def _handle_echo_reply(self, payload: bytes):
        """
        Handle echo reply packet.
        
        Args:
            payload: Echo payload
        """
        # find corresponding request
        # note: in real implementation, would extract sequence from packet
        for seq, timestamp in list(self.echo_responses.items()):
            latency = time.time() - timestamp
            self.echo_latencies.append(latency)
            del self.echo_responses[seq]
            
            logger.info(f"echo reply received, latency={latency*1000:.2f}ms")
            break
    
    def _handle_data_packet(self, payload: bytes):
        """
        Handle regular data packet.
        
        Args:
            payload: Packet payload
        """
        # in future phases, this would process routed packets
        logger.debug(f"data packet received, size={len(payload)}")
        
        # add to inbound queue for application processing
        self.inbound_queue.put(payload)
    
    def _send_loop(self):
        """Main sending loop for outbound packets."""
        while self.running:
            try:
                # get packet from queue
                try:
                    packet_data = self.outbound_queue.get(timeout=0.1)
                except Empty:
                    continue
                
                # send via callback if available
                if self.send_callback:
                    # wrap in protocol message
                    message = ProtocolMessage(
                        msg_type=MessageType.DATA,
                        payload={
                            "data": base64.b64encode(packet_data).decode('utf-8')
                        }
                    )
                    
                    self.send_callback(message)
                    
                    logger.debug(f"packet sent via callback, size={len(packet_data)}")
                else:
                    logger.warning("no send callback configured")
                
            except Exception as e:
                logger.error(f"send loop error: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get packet handler statistics."""
        avg_latency = 0
        if self.echo_latencies:
            avg_latency = sum(self.echo_latencies) / len(self.echo_latencies)
        
        return {
            **self.stats.to_dict(),
            "echo_pending": len(self.echo_responses),
            "echo_count": len(self.echo_latencies),
            "echo_avg_latency_ms": avg_latency * 1000,
            "running": self.running
        }
    
    def get_received_data(self, timeout: float = 0.1) -> Optional[bytes]:
        """
        Get received data from inbound queue.
        
        Args:
            timeout: Queue get timeout
            
        Returns:
            Received data or None
        """
        try:
            return self.inbound_queue.get(timeout=timeout)
        except Empty:
            return None


class PacketTester:
    """Utility class for testing packet functionality."""
    
    def __init__(self, packet_handler: ClientPacketHandler):
        """
        Initialize packet tester.
        
        Args:
            packet_handler: Client packet handler
        """
        self.packet_handler = packet_handler
        self.test_results: Dict[str, Any] = {}
        
    def run_echo_test(
        self,
        count: int = 10,
        payload_size: int = 64,
        interval: float = 1.0
    ) -> Dict[str, Any]:
        """
        Run echo test with server.
        
        Args:
            count: Number of echo requests
            payload_size: Size of echo payload
            interval: Interval between requests
            
        Returns:
            Test results
        """
        logger.info(
            f"starting echo test: count={count}, size={payload_size}, interval={interval}"
        )
        
        results = {
            "count": count,
            "payload_size": payload_size,
            "sent": 0,
            "received": 0,
            "lost": 0,
            "latencies": [],
            "min_latency_ms": 0,
            "max_latency_ms": 0,
            "avg_latency_ms": 0,
            "packet_loss_percent": 0
        }
        
        # clear previous latencies
        self.packet_handler.echo_latencies.clear()
        
        # send echo requests
        for i in range(count):
            payload = b"x" * payload_size
            self.packet_handler.send_echo_request(payload)
            results["sent"] += 1
            
            if i < count - 1:
                time.sleep(interval)
        
        # wait for responses
        time.sleep(interval * 2)
        
        # collect results
        latencies = self.packet_handler.echo_latencies[-count:]
        results["received"] = len(latencies)
        results["lost"] = count - len(latencies)
        results["packet_loss_percent"] = (results["lost"] / count) * 100
        
        if latencies:
            results["latencies"] = [l * 1000 for l in latencies]  # convert to ms
            results["min_latency_ms"] = min(results["latencies"])
            results["max_latency_ms"] = max(results["latencies"])
            results["avg_latency_ms"] = sum(results["latencies"]) / len(results["latencies"])
        
        logger.info(
            f"echo test complete: {results['received']}/{count} received, "
            f"avg latency={results['avg_latency_ms']:.2f}ms, "
            f"loss={results['packet_loss_percent']:.1f}%"
        )
        
        return results
    
    def run_throughput_test(
        self,
        duration: float = 10.0,
        packet_size: int = 1400
    ) -> Dict[str, Any]:
        """
        Run throughput test.
        
        Args:
            duration: Test duration in seconds
            packet_size: Size of each packet
            
        Returns:
            Test results
        """
        logger.info(
            f"starting throughput test: duration={duration}s, packet_size={packet_size}"
        )
        
        start_time = time.time()
        packets_sent = 0
        bytes_sent = 0
        
        # send packets for duration
        while time.time() - start_time < duration:
            data = b"t" * packet_size
            self.packet_handler.send_data(data)
            packets_sent += 1
            bytes_sent += len(data)
            
            # small delay to avoid overwhelming
            time.sleep(0.001)
        
        elapsed = time.time() - start_time
        
        results = {
            "duration_s": elapsed,
            "packets_sent": packets_sent,
            "bytes_sent": bytes_sent,
            "packets_per_second": packets_sent / elapsed,
            "throughput_mbps": (bytes_sent * 8) / (elapsed * 1000000)
        }
        
        logger.info(
            f"throughput test complete: {packets_sent} packets, "
            f"{results['throughput_mbps']:.2f} Mbps"
        )
        
        return results
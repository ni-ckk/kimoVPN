"""
Packet routing logic for VPN server.
"""

import base64
import threading
import queue
from typing import Dict, Optional, Any
from collections import defaultdict
from datetime import datetime

from structlog import get_logger
from scapy.all import IP

from ..common.ip_packet import IPPacketHandler, PacketFilter
from ..common.protocol import ProtocolMessage, MessageType
from .ip_pool import IPPool
from .tun_interface import create_tun_interface

logger = get_logger()


class PacketRouter:
    """Routes packets between clients and the internet."""
    
    def __init__(
        self,
        ip_pool: IPPool,
        tun_interface: Optional[Any] = None,
        enable_nat: bool = True
    ):
        """
        Initialize packet router.
        
        Args:
            ip_pool: IP address pool
            tun_interface: TUN interface instance
            enable_nat: Enable NAT for outgoing packets
        """
        self.ip_pool = ip_pool
        self.tun_interface = tun_interface
        self.enable_nat = enable_nat
        
        # packet handler
        self.packet_handler = IPPacketHandler(str(ip_pool.network))
        self.packet_filter = PacketFilter()
        
        # client connections: ip -> client_handler
        self.clients: Dict[str, Any] = {}
        self.lock = threading.Lock()
        
        # packet queues
        self.inbound_queue = queue.Queue()  # from clients
        self.outbound_queue = queue.Queue()  # to clients
        
        # statistics
        self.stats = defaultdict(lambda: {
            "packets_in": 0,
            "packets_out": 0,
            "bytes_in": 0,
            "bytes_out": 0,
            "last_activity": None
        })
        
        self.running = False
        self.routing_thread = None
        
        logger.info(
            "packet router initialized",
            network=str(ip_pool.network),
            nat_enabled=enable_nat
        )
    
    def register_client(self, client_ip: str, client_handler: Any):
        """
        Register a client for routing.
        
        Args:
            client_ip: Client's virtual IP
            client_handler: Client connection handler
        """
        with self.lock:
            self.clients[client_ip] = client_handler
            logger.info(f"registered client {client_ip} for routing")
    
    def unregister_client(self, client_ip: str):
        """
        Unregister a client from routing.
        
        Args:
            client_ip: Client's virtual IP
        """
        with self.lock:
            if client_ip in self.clients:
                del self.clients[client_ip]
                logger.info(f"unregistered client {client_ip} from routing")
    
    def start(self):
        """Start packet routing."""
        if self.running:
            logger.warning("packet router already running")
            return
        
        self.running = True
        
        # start routing thread
        self.routing_thread = threading.Thread(
            target=self._routing_loop,
            daemon=True
        )
        self.routing_thread.start()
        
        # setup tun interface callback if available
        if self.tun_interface:
            self.tun_interface.on_packet_received = self._handle_tun_packet
        
        logger.info("packet router started")
    
    def stop(self):
        """Stop packet routing."""
        self.running = False
        
        if self.routing_thread:
            self.routing_thread.join(timeout=2)
        
        logger.info("packet router stopped")
    
    def route_from_client(self, client_ip: str, packet_data: bytes):
        """
        Route packet from client to internet.
        
        Args:
            client_ip: Source client IP
            packet_data: Raw packet data
        """
        try:
            # parse packet
            packet = self.packet_handler.parse_packet(packet_data)
            if not packet:
                logger.warning(f"invalid packet from {client_ip}")
                return
            
            # verify source ip matches client
            if packet.src != client_ip:
                logger.warning(
                    f"source ip mismatch: expected {client_ip}, got {packet.src}"
                )
                return
            
            # check if destination is valid
            if not self.packet_handler.is_valid_destination(packet):
                logger.debug(f"invalid destination {packet.dst} from {client_ip}")
                return
            
            # apply packet filter
            if not self.packet_filter.check_packet(packet):
                logger.debug(f"packet filtered from {client_ip} to {packet.dst}")
                return
            
            # update statistics
            self._update_stats(client_ip, "out", packet)
            
            # perform nat if enabled
            if self.enable_nat:
                # rewrite source to server's public ip
                # (handled by linux nat/masquerade)
                pass
            
            # forward to tun interface
            if self.tun_interface and self.tun_interface.running:
                self.tun_interface.write_packet(packet_data)
                logger.debug(
                    f"routed packet: {client_ip} -> {packet.dst} ({len(packet_data)} bytes)"
                )
            else:
                logger.warning("tun interface not available for routing")
            
        except Exception as e:
            logger.error(f"error routing packet from client: {e}")
    
    def route_to_client(self, packet_data: bytes):
        """
        Route packet from internet to client.
        
        Args:
            packet_data: Raw packet data
        """
        try:
            # parse packet
            packet = self.packet_handler.parse_packet(packet_data)
            if not packet:
                logger.warning("invalid packet from internet")
                return
            
            # find destination client
            dst_ip = packet.dst
            
            with self.lock:
                client_handler = self.clients.get(dst_ip)
            
            if not client_handler:
                logger.debug(f"no client found for {dst_ip}")
                return
            
            # apply packet filter
            if not self.packet_filter.check_packet(packet):
                logger.debug(f"packet filtered to {dst_ip} from {packet.src}")
                return
            
            # update statistics
            self._update_stats(dst_ip, "in", packet)
            
            # forward to client
            client_handler.send_packet(packet_data)
            logger.debug(
                f"routed packet: {packet.src} -> {dst_ip} ({len(packet_data)} bytes)"
            )
            
        except Exception as e:
            logger.error(f"error routing packet to client: {e}")
    
    def _handle_tun_packet(self, packet_data: bytes):
        """
        Handle packet received from TUN interface.
        
        Args:
            packet_data: Raw packet data
        """
        # route to appropriate client
        self.route_to_client(packet_data)
    
    def _routing_loop(self):
        """Main routing loop."""
        logger.debug("routing loop started")
        
        while self.running:
            try:
                # process inbound queue (from clients to internet)
                try:
                    client_ip, packet_data = self.inbound_queue.get(timeout=0.1)
                    self.route_from_client(client_ip, packet_data)
                except queue.Empty:
                    pass
                
                # process outbound queue (from internet to clients)
                try:
                    packet_data = self.outbound_queue.get(timeout=0.1)
                    self.route_to_client(packet_data)
                except queue.Empty:
                    pass
                
            except Exception as e:
                logger.error(f"error in routing loop: {e}")
        
        logger.debug("routing loop stopped")
    
    def _update_stats(self, client_ip: str, direction: str, packet: IP):
        """Update routing statistics (thread-safe)."""
        with self.lock:
            stats = self.stats[client_ip]
            
            if direction == "in":
                stats["packets_in"] += 1
                stats["bytes_in"] += len(packet)
            else:
                stats["packets_out"] += 1
                stats["bytes_out"] += len(packet)
            
            stats["last_activity"] = datetime.now()
    
    def get_stats(self, client_ip: Optional[str] = None) -> Dict[str, Any]:
        """
        Get routing statistics.
        
        Args:
            client_ip: Specific client IP or None for all
            
        Returns:
            Statistics dictionary
        """
        if client_ip:
            return dict(self.stats.get(client_ip, {}))
        else:
            return {ip: dict(stats) for ip, stats in self.stats.items()}
    
    def add_filter_rule(self, **kwargs):
        """Add packet filter rule."""
        self.packet_filter.add_rule(**kwargs)
        logger.info(f"added filter rule: {kwargs}")
    
    def clear_filter_rules(self):
        """Clear all filter rules."""
        self.packet_filter.rules.clear()
        logger.info("cleared all filter rules")


class ClientHandler:
    """Handles packet communication with a specific client."""
    
    def __init__(
        self,
        client_connection: Any,
        router: PacketRouter,
        client_ip: str
    ):
        """
        Initialize client handler.
        
        Args:
            client_connection: Client connection object
            router: Packet router instance
            client_ip: Client's virtual IP
        """
        self.client_connection = client_connection
        self.router = router
        self.client_ip = client_ip
        
        # register with router
        router.register_client(client_ip, self)
    
    def send_packet(self, packet_data: bytes):
        """
        Send packet to client.
        
        Args:
            packet_data: Raw packet data
        """
        try:
            # wrap in data message and send to client
            message = ProtocolMessage(
                msg_type=MessageType.DATA,
                sequence=0,  # will be set by connection
                payload={"data": base64.b64encode(packet_data).decode()}
            )
            
            self.client_connection.send_message(message)
            
        except Exception as e:
            logger.error(f"failed to send packet to client {self.client_ip}: {e}")
    
    def handle_packet_from_client(self, packet_data: bytes):
        """
        Handle packet received from client.
        
        Args:
            packet_data: Raw packet data
        """
        # route through router
        self.router.route_from_client(self.client_ip, packet_data)
    
    def cleanup(self):
        """Clean up client handler."""
        self.router.unregister_client(self.client_ip)
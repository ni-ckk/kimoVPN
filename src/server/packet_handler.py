"""
Server-side packet handling and echo functionality.

This module processes data packets received from clients,
including echo mode for testing packet flow.
"""

import time
import threading
from typing import Optional, Dict, Any, Callable
from queue import Queue, Empty

from src.common.packet import (
    PacketType,
    PacketEncoder,
    PacketDecoder,
    PacketEncryptor,
    VPNPacket,
    PacketStats
)
from src.common.logging import get_logger

logger = get_logger(__name__)


class PacketHandler:
    """Handles packet processing on the server side."""
    
    def __init__(
        self,
        encryptor: Optional[PacketEncryptor] = None,
        echo_mode: bool = True
    ):
        """
        Initialize packet handler.
        
        Args:
            encryptor: Packet encryptor for secure communication
            echo_mode: Enable echo mode for testing
        """
        self.encryptor = encryptor or PacketEncryptor()
        self.encoder = PacketEncoder(self.encryptor)
        self.decoder = PacketDecoder(self.encryptor)
        self.echo_mode = echo_mode
        
        # packet queues
        self.inbound_queue = Queue()
        self.outbound_queue = Queue()
        
        # statistics
        self.stats = PacketStats()
        self.client_stats: Dict[str, PacketStats] = {}
        
        # processing thread
        self.running = False
        self.process_thread = None
        
        # packet handlers by type
        self.handlers: Dict[PacketType, Callable] = {
            PacketType.DATA: self._handle_data_packet,
            PacketType.ECHO_REQUEST: self._handle_echo_request,
            PacketType.ECHO_REPLY: self._handle_echo_reply,
            PacketType.KEEPALIVE: self._handle_keepalive,
        }
        
        logger.info(
            "packet handler initialized",
            echo_mode=echo_mode
        )
    
    def start(self):
        """Start packet processing."""
        if self.running:
            return
        
        self.running = True
        self.process_thread = threading.Thread(
            target=self._process_loop,
            daemon=True
        )
        self.process_thread.start()
        logger.info("packet handler started")
    
    def stop(self):
        """Stop packet processing."""
        self.running = False
        if self.process_thread:
            self.process_thread.join(timeout=5)
        logger.info("packet handler stopped")
    
    def process_packet(
        self,
        data: bytes,
        client_id: str
    ) -> Optional[bytes]:
        """
        Process incoming packet from client.
        
        Args:
            data: Raw packet data
            client_id: Client identifier
            
        Returns:
            Response packet if any
        """
        try:
            # decode packet
            packet_type, payload = self.decoder.decode(data)
            
            # update stats
            if client_id not in self.client_stats:
                self.client_stats[client_id] = PacketStats()
            
            self.client_stats[client_id].update_received(
                len(data),
                decrypted=True
            )
            self.stats.update_received(len(data), decrypted=True)
            
            logger.debug(
                "packet received",
                packet_type=packet_type.name,
                client_id=client_id,
                size=len(data)
            )
            
            # handle packet based on type
            handler = self.handlers.get(packet_type)
            if handler:
                response = handler(payload, client_id)
                if response:
                    # update send stats
                    self.client_stats[client_id].update_sent(
                        len(response),
                        encrypted=True
                    )
                    self.stats.update_sent(len(response), encrypted=True)
                    return response
            else:
                logger.warning(
                    "unknown packet type",
                    packet_type=packet_type,
                    client_id=client_id
                )
            
            return None
            
        except Exception as e:
            logger.error(
                "packet processing failed",
                error=str(e),
                client_id=client_id
            )
            self.stats.decryption_errors += 1
            return None
    
    def _handle_data_packet(
        self,
        payload: bytes,
        client_id: str
    ) -> Optional[bytes]:
        """
        Handle regular data packet.
        
        Args:
            payload: Packet payload
            client_id: Client identifier
            
        Returns:
            Response packet if any
        """
        if self.echo_mode:
            # echo back the data
            logger.debug(
                "echoing data packet",
                client_id=client_id,
                size=len(payload)
            )
            return self.encoder.encode(
                payload,
                PacketType.DATA,
                encrypt=True
            )
        else:
            # in future phases, this would route the packet
            logger.debug(
                "data packet received (routing not implemented)",
                client_id=client_id,
                size=len(payload)
            )
            return None
    
    def _handle_echo_request(
        self,
        payload: bytes,
        client_id: str
    ) -> Optional[bytes]:
        """
        Handle echo request packet.
        
        Args:
            payload: Echo payload
            client_id: Client identifier
            
        Returns:
            Echo reply packet
        """
        logger.debug(
            "echo request received",
            client_id=client_id,
            size=len(payload)
        )
        
        # create echo reply with same payload
        return self.encoder.create_echo_reply(payload)
    
    def _handle_echo_reply(
        self,
        payload: bytes,
        client_id: str
    ) -> Optional[bytes]:
        """
        Handle echo reply packet.
        
        Args:
            payload: Echo payload
            client_id: Client identifier
            
        Returns:
            None (no response needed)
        """
        logger.debug(
            "echo reply received",
            client_id=client_id,
            size=len(payload)
        )
        return None
    
    def _handle_keepalive(
        self,
        payload: bytes,
        client_id: str
    ) -> Optional[bytes]:
        """
        Handle keepalive packet.
        
        Args:
            payload: Keepalive payload
            client_id: Client identifier
            
        Returns:
            Keepalive response
        """
        logger.debug("keepalive received", client_id=client_id)
        
        # respond with keepalive
        return self.encoder.encode(
            b"",
            PacketType.KEEPALIVE,
            encrypt=False
        )
    
    def _process_loop(self):
        """Main packet processing loop."""
        while self.running:
            try:
                # process inbound packets
                try:
                    item = self.inbound_queue.get(timeout=0.1)
                    if item:
                        data, client_id = item
                        response = self.process_packet(data, client_id)
                        if response:
                            self.outbound_queue.put((response, client_id))
                except Empty:
                    pass
                
            except Exception as e:
                logger.error(f"process loop error: {e}")
    
    def queue_inbound(self, data: bytes, client_id: str):
        """
        Queue inbound packet for processing.
        
        Args:
            data: Packet data
            client_id: Client identifier
        """
        self.inbound_queue.put((data, client_id))
    
    def get_outbound(self, timeout: float = 0.1) -> Optional[tuple]:
        """
        Get outbound packet from queue.
        
        Args:
            timeout: Queue get timeout
            
        Returns:
            Tuple of (data, client_id) or None
        """
        try:
            return self.outbound_queue.get(timeout=timeout)
        except Empty:
            return None
    
    def get_stats(self) -> Dict[str, Any]:
        """Get packet handler statistics."""
        return {
            "global": self.stats.to_dict(),
            "clients": {
                client_id: stats.to_dict()
                for client_id, stats in self.client_stats.items()
            },
            "echo_mode": self.echo_mode,
            "running": self.running
        }
    
    def get_client_stats(self, client_id: str) -> Optional[Dict[str, Any]]:
        """Get statistics for specific client."""
        if client_id in self.client_stats:
            return self.client_stats[client_id].to_dict()
        return None


class PacketRouter:
    """Routes packets between clients (future implementation)."""
    
    def __init__(self):
        """Initialize packet router."""
        self.routing_table: Dict[str, str] = {}
        self.client_handlers: Dict[str, PacketHandler] = {}
        logger.info("packet router initialized")
    
    def add_client(self, client_id: str, virtual_ip: str):
        """
        Add client to routing table.
        
        Args:
            client_id: Client identifier
            virtual_ip: Client's virtual IP address
        """
        self.routing_table[virtual_ip] = client_id
        logger.info(
            "client added to routing table",
            client_id=client_id,
            virtual_ip=virtual_ip
        )
    
    def remove_client(self, client_id: str):
        """
        Remove client from routing table.
        
        Args:
            client_id: Client identifier
        """
        # find and remove virtual IP
        for vip, cid in list(self.routing_table.items()):
            if cid == client_id:
                del self.routing_table[vip]
                logger.info(
                    "client removed from routing table",
                    client_id=client_id,
                    virtual_ip=vip
                )
                break
    
    def route_packet(
        self,
        source_ip: str,
        dest_ip: str,
        payload: bytes
    ) -> Optional[str]:
        """
        Route packet to destination client.
        
        Args:
            source_ip: Source virtual IP
            dest_ip: Destination virtual IP
            payload: Packet payload
            
        Returns:
            Destination client ID if found
        """
        dest_client = self.routing_table.get(dest_ip)
        if dest_client:
            logger.debug(
                "routing packet",
                source=source_ip,
                dest=dest_ip,
                client=dest_client
            )
            return dest_client
        else:
            logger.warning(
                "no route to destination",
                source=source_ip,
                dest=dest_ip
            )
            return None
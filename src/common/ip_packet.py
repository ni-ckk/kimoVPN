"""
IP packet manipulation utilities using Scapy.
"""

import struct
from typing import Optional, Tuple, Dict, Any
from ipaddress import IPv4Address, IPv4Network, ip_address

from scapy.all import IP, TCP, UDP, ICMP, Raw, Ether
from structlog import get_logger

logger = get_logger()


class IPPacketHandler:
    """Handles IP packet parsing and manipulation."""
    
    def __init__(self, network: str = "10.8.0.0/24"):
        """
        Initialize IP packet handler.
        
        Args:
            network: Virtual network in CIDR notation
        """
        self.network = IPv4Network(network)
        self.mtu = 1500  # standard ethernet mtu
        
    def parse_packet(self, data: bytes) -> Optional[IP]:
        """
        Parse raw bytes into IP packet.
        
        Args:
            data: Raw packet data
            
        Returns:
            Parsed IP packet or None if invalid
        """
        try:
            # try to parse as IP packet
            packet = IP(data)
            return packet
        except Exception as e:
            logger.debug(f"failed to parse packet: {e}")
            return None
    
    def build_packet(
        self,
        src: str,
        dst: str,
        payload: bytes,
        proto: str = "tcp"
    ) -> bytes:
        """
        Build an IP packet.
        
        Args:
            src: Source IP address
            dst: Destination IP address  
            payload: Packet payload
            proto: Protocol (tcp/udp/icmp)
            
        Returns:
            Raw packet bytes
        """
        try:
            packet = IP(src=src, dst=dst)
            
            if proto == "tcp":
                packet = packet / TCP() / Raw(payload)
            elif proto == "udp":
                packet = packet / UDP() / Raw(payload)
            elif proto == "icmp":
                packet = packet / ICMP() / Raw(payload)
            else:
                packet = packet / Raw(payload)
            
            return bytes(packet)
            
        except Exception as e:
            logger.error(f"failed to build packet: {e}")
            raise
    
    def is_valid_destination(self, packet: IP) -> bool:
        """
        Check if packet destination is valid for routing.
        
        Args:
            packet: IP packet
            
        Returns:
            True if destination is routable
        """
        try:
            dst_ip = ip_address(packet.dst)
            
            # don't route to private networks (except our VPN network)
            if dst_ip.is_private and dst_ip not in self.network:
                return False
            
            # don't route to multicast or reserved
            if dst_ip.is_multicast or dst_ip.is_reserved:
                return False
            
            return True
            
        except Exception as e:
            logger.debug(f"invalid destination check: {e}")
            return False
    
    def rewrite_source(self, packet: IP, new_src: str) -> IP:
        """
        Rewrite source IP address.
        
        Args:
            packet: Original packet
            new_src: New source IP
            
        Returns:
            Modified packet with recalculated checksums
        """
        packet.src = new_src
        # force checksum recalculation by rebuilding packet
        # this is more reliable than deleting checksum fields
        return IP(bytes(packet))
    
    def rewrite_destination(self, packet: IP, new_dst: str) -> IP:
        """
        Rewrite destination IP address.
        
        Args:
            packet: Original packet
            new_dst: New destination IP
            
        Returns:
            Modified packet with recalculated checksums
        """
        packet.dst = new_dst
        # force checksum recalculation by rebuilding packet
        # this is more reliable than deleting checksum fields
        return IP(bytes(packet))
    
    def get_packet_info(self, packet: IP) -> Dict[str, Any]:
        """
        Extract packet information.
        
        Args:
            packet: IP packet
            
        Returns:
            Packet information dictionary
        """
        info = {
            "version": packet.version,
            "src": packet.src,
            "dst": packet.dst,
            "proto": packet.proto,
            "len": packet.len,
            "ttl": packet.ttl,
        }
        
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            info["proto_name"] = "TCP"
            info["sport"] = tcp.sport
            info["dport"] = tcp.dport
            info["flags"] = tcp.flags
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            info["proto_name"] = "UDP"
            info["sport"] = udp.sport
            info["dport"] = udp.dport
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            info["proto_name"] = "ICMP"
            info["type"] = icmp.type
            info["code"] = icmp.code
        else:
            info["proto_name"] = f"Protocol_{packet.proto}"
        
        return info
    
    def fragment_packet(self, packet: IP, mtu: int = 1500) -> list:
        """
        Fragment packet if needed.
        
        Args:
            packet: IP packet
            mtu: Maximum transmission unit
            
        Returns:
            List of fragments
        """
        if len(packet) <= mtu:
            return [packet]
        
        # use scapy's fragment function
        return packet.fragment(mtu)
    
    def reassemble_fragments(self, fragments: list) -> Optional[IP]:
        """
        Reassemble packet fragments.
        
        Note: Scapy doesn't provide a simple defragment() method.
        For production use, implement proper fragment tracking.
        
        Args:
            fragments: List of packet fragments
            
        Returns:
            Reassembled packet or None
        """
        if not fragments:
            return None
        
        # for now, just return first fragment as a placeholder
        # in production, implement proper reassembly logic
        # tracking fragments by ID and offset
        logger.warning("fragment reassembly not fully implemented - returning first fragment")
        return fragments[0] if fragments else None


class PacketFilter:
    """Filter packets based on rules."""
    
    def __init__(self):
        """Initialize packet filter."""
        self.rules = []
        
    def add_rule(
        self,
        action: str,
        src: Optional[str] = None,
        dst: Optional[str] = None,
        proto: Optional[str] = None,
        port: Optional[int] = None
    ):
        """
        Add filter rule.
        
        Args:
            action: allow/deny
            src: Source IP/network
            dst: Destination IP/network
            proto: Protocol
            port: Port number
        """
        rule = {
            "action": action,
            "src": IPv4Network(src) if src else None,
            "dst": IPv4Network(dst) if dst else None,
            "proto": proto,
            "port": port
        }
        self.rules.append(rule)
    
    def check_packet(self, packet: IP) -> bool:
        """
        Check if packet is allowed.
        
        Args:
            packet: IP packet
            
        Returns:
            True if packet is allowed
        """
        # default allow if no rules
        if not self.rules:
            return True
        
        for rule in self.rules:
            if self._match_rule(packet, rule):
                return rule["action"] == "allow"
        
        # default deny
        return False
    
    def _match_rule(self, packet: IP, rule: dict) -> bool:
        """Check if packet matches rule."""
        # check source
        if rule["src"]:
            src_ip = ip_address(packet.src)
            if src_ip not in rule["src"]:
                return False
        
        # check destination
        if rule["dst"]:
            dst_ip = ip_address(packet.dst)
            if dst_ip not in rule["dst"]:
                return False
        
        # check protocol
        if rule["proto"]:
            if rule["proto"] == "tcp" and not packet.haslayer(TCP):
                return False
            elif rule["proto"] == "udp" and not packet.haslayer(UDP):
                return False
            elif rule["proto"] == "icmp" and not packet.haslayer(ICMP):
                return False
        
        # check port
        if rule["port"]:
            if packet.haslayer(TCP):
                if packet[TCP].dport != rule["port"]:
                    return False
            elif packet.haslayer(UDP):
                if packet[UDP].dport != rule["port"]:
                    return False
        
        return True
"""
Packet structure and encryption for VPN data transfer.

This module implements the packet format for secure data transmission
between client and server, using PyNaCl for encryption.
"""

import struct
import time
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional, Tuple, Any

import nacl.secret
import nacl.utils
from nacl.encoding import RawEncoder
from pydantic import BaseModel, Field

from src.common.logging import get_logger

logger = get_logger(__name__)


class PacketType(IntEnum):
    """VPN packet types."""
    DATA = 0x01  # regular data packet
    ECHO_REQUEST = 0x02  # echo request for testing
    ECHO_REPLY = 0x03  # echo reply
    CONTROL = 0x04  # control message
    FRAGMENT = 0x05  # fragmented packet
    KEEPALIVE = 0x06  # keepalive packet


class PacketFlags(IntEnum):
    """Packet flags for additional options."""
    NONE = 0x00
    ENCRYPTED = 0x01  # packet is encrypted
    COMPRESSED = 0x02  # packet is compressed (future)
    FRAGMENTED = 0x04  # packet is part of fragment
    LAST_FRAGMENT = 0x08  # last fragment in sequence


@dataclass
class PacketHeader:
    """VPN packet header structure.
    
    Format (16 bytes):
    - version: 1 byte
    - type: 1 byte  
    - flags: 1 byte
    - reserved: 1 byte
    - sequence: 4 bytes
    - timestamp: 4 bytes
    - length: 4 bytes
    """
    version: int = 1
    packet_type: PacketType = PacketType.DATA
    flags: int = PacketFlags.NONE
    sequence: int = 0
    timestamp: int = 0
    length: int = 0
    
    HEADER_SIZE = 16
    HEADER_FORMAT = "!BBBBIII"  # network byte order
    
    def pack(self) -> bytes:
        """Pack header into bytes."""
        return struct.pack(
            self.HEADER_FORMAT,
            self.version,
            self.packet_type,
            self.flags,
            0,  # reserved
            self.sequence,
            self.timestamp or int(time.time()),
            self.length
        )
    
    @classmethod
    def unpack(cls, data: bytes) -> "PacketHeader":
        """Unpack header from bytes."""
        if len(data) < cls.HEADER_SIZE:
            raise ValueError(f"Invalid header size: {len(data)}")
        
        (version, ptype, flags, _, 
         sequence, timestamp, length) = struct.unpack(
            cls.HEADER_FORMAT, data[:cls.HEADER_SIZE]
        )
        
        return cls(
            version=version,
            packet_type=PacketType(ptype),
            flags=flags,
            sequence=sequence,
            timestamp=timestamp,
            length=length
        )


class VPNPacket(BaseModel):
    """Complete VPN packet with header and payload."""
    header: PacketHeader = Field(..., description="Packet header")
    payload: bytes = Field(..., description="Packet payload")
    
    class Config:
        arbitrary_types_allowed = True
    
    def to_bytes(self) -> bytes:
        """Convert packet to bytes."""
        header_bytes = self.header.pack()
        return header_bytes + self.payload
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "VPNPacket":
        """Create packet from bytes."""
        if len(data) < PacketHeader.HEADER_SIZE:
            raise ValueError("Data too short for packet")
        
        header = PacketHeader.unpack(data)
        payload = data[PacketHeader.HEADER_SIZE:]
        
        if len(payload) != header.length:
            raise ValueError(
                f"Payload size mismatch: expected {header.length}, got {len(payload)}"
            )
        
        return cls(header=header, payload=payload)


class PacketEncryptor:
    """Handles packet encryption using PyNaCl."""
    
    def __init__(self, shared_key: Optional[bytes] = None):
        """
        Initialize encryptor with shared key.
        
        Args:
            shared_key: 32-byte shared secret key
        """
        if shared_key:
            if len(shared_key) != nacl.secret.SecretBox.KEY_SIZE:
                raise ValueError(
                    f"Key must be {nacl.secret.SecretBox.KEY_SIZE} bytes"
                )
            self.box = nacl.secret.SecretBox(shared_key)
        else:
            # generate new key for this session
            self.shared_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
            self.box = nacl.secret.SecretBox(self.shared_key)
        
        logger.debug("packet encryptor initialized")
    
    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt data with authentication.
        
        Args:
            data: Data to encrypt
            
        Returns:
            Encrypted data with nonce and MAC
        """
        try:
            encrypted = self.box.encrypt(data, encoder=RawEncoder)
            return encrypted
        except Exception as e:
            logger.error(f"encryption failed: {e}")
            raise
    
    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypt and verify data.
        
        Args:
            data: Encrypted data with nonce and MAC
            
        Returns:
            Decrypted data
            
        Raises:
            nacl.exceptions.CryptoError: If decryption or verification fails
        """
        try:
            decrypted = self.box.decrypt(data, encoder=RawEncoder)
            return decrypted
        except Exception as e:
            logger.error(f"decryption failed: {e}")
            raise
    
    def get_shared_key(self) -> bytes:
        """Get the shared encryption key."""
        return self.box._key


class PacketEncoder:
    """Encodes packets for transmission."""
    
    def __init__(self, encryptor: Optional[PacketEncryptor] = None):
        """
        Initialize encoder.
        
        Args:
            encryptor: Optional packet encryptor
        """
        self.encryptor = encryptor
        self.sequence = 0
    
    def encode(
        self, 
        data: bytes, 
        packet_type: PacketType = PacketType.DATA,
        encrypt: bool = True
    ) -> bytes:
        """
        Encode data into packet.
        
        Args:
            data: Raw data to encode
            packet_type: Type of packet
            encrypt: Whether to encrypt payload
            
        Returns:
            Complete packet as bytes
        """
        # encrypt if encryptor available and requested
        if encrypt and self.encryptor:
            payload = self.encryptor.encrypt(data)
            flags = PacketFlags.ENCRYPTED
        else:
            payload = data
            flags = PacketFlags.NONE
        
        # create header
        header = PacketHeader(
            packet_type=packet_type,
            flags=flags,
            sequence=self.sequence,
            timestamp=int(time.time()),
            length=len(payload)
        )
        
        self.sequence += 1
        
        # create packet
        packet = VPNPacket(header=header, payload=payload)
        
        return packet.to_bytes()
    
    def create_echo_request(self, data: bytes) -> bytes:
        """Create echo request packet."""
        return self.encode(data, PacketType.ECHO_REQUEST, encrypt=True)
    
    def create_echo_reply(self, data: bytes) -> bytes:
        """Create echo reply packet."""
        return self.encode(data, PacketType.ECHO_REPLY, encrypt=True)


class PacketDecoder:
    """Decodes received packets."""
    
    def __init__(self, encryptor: Optional[PacketEncryptor] = None):
        """
        Initialize decoder.
        
        Args:
            encryptor: Optional packet encryptor for decryption
        """
        self.encryptor = encryptor
    
    def decode(self, data: bytes) -> Tuple[PacketType, bytes]:
        """
        Decode packet from bytes.
        
        Args:
            data: Raw packet bytes
            
        Returns:
            Tuple of (packet_type, payload)
        """
        # parse packet
        packet = VPNPacket.from_bytes(data)
        
        # decrypt if needed
        if packet.header.flags & PacketFlags.ENCRYPTED:
            if not self.encryptor:
                raise ValueError("Packet is encrypted but no encryptor available")
            payload = self.encryptor.decrypt(packet.payload)
        else:
            payload = packet.payload
        
        return packet.header.packet_type, payload
    
    def decode_packet(self, data: bytes) -> VPNPacket:
        """
        Decode and return full packet structure.
        
        Args:
            data: Raw packet bytes
            
        Returns:
            Decoded VPNPacket
        """
        packet = VPNPacket.from_bytes(data)
        
        # decrypt payload if needed
        if packet.header.flags & PacketFlags.ENCRYPTED and self.encryptor:
            packet.payload = self.encryptor.decrypt(packet.payload)
            # clear encrypted flag after decryption
            packet.header.flags &= ~PacketFlags.ENCRYPTED
        
        return packet


class PacketFragmenter:
    """Handles packet fragmentation for large payloads."""
    
    DEFAULT_MTU = 1400  # default MTU size
    
    @classmethod
    def fragment(
        cls, 
        data: bytes, 
        mtu: int = DEFAULT_MTU,
        packet_type: PacketType = PacketType.DATA
    ) -> list[PacketHeader]:
        """
        Fragment data into multiple packets.
        
        Args:
            data: Data to fragment
            mtu: Maximum transmission unit
            packet_type: Type of packet
            
        Returns:
            List of packet headers with fragmented data
        """
        # calculate max payload size (MTU - header)
        max_payload = mtu - PacketHeader.HEADER_SIZE
        
        if len(data) <= max_payload:
            # no fragmentation needed
            return []
        
        fragments = []
        offset = 0
        sequence = 0
        
        while offset < len(data):
            chunk = data[offset:offset + max_payload]
            
            # determine flags
            flags = PacketFlags.FRAGMENTED
            if offset + len(chunk) >= len(data):
                flags |= PacketFlags.LAST_FRAGMENT
            
            header = PacketHeader(
                packet_type=PacketType.FRAGMENT,
                flags=flags,
                sequence=sequence,
                length=len(chunk)
            )
            
            fragments.append((header, chunk))
            offset += len(chunk)
            sequence += 1
        
        return fragments


# performance statistics
class PacketStats(BaseModel):
    """Packet transmission statistics."""
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_encrypted: int = 0
    packets_decrypted: int = 0
    encryption_errors: int = 0
    decryption_errors: int = 0
    last_packet_time: Optional[float] = None
    
    def update_sent(self, packet_size: int, encrypted: bool = False):
        """Update statistics for sent packet."""
        self.packets_sent += 1
        self.bytes_sent += packet_size
        if encrypted:
            self.packets_encrypted += 1
        self.last_packet_time = time.time()
    
    def update_received(self, packet_size: int, decrypted: bool = False):
        """Update statistics for received packet."""
        self.packets_received += 1
        self.bytes_received += packet_size
        if decrypted:
            self.packets_decrypted += 1
        self.last_packet_time = time.time()
    
    def to_dict(self) -> dict:
        """Convert stats to dictionary."""
        return {
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "packets_encrypted": self.packets_encrypted,
            "packets_decrypted": self.packets_decrypted,
            "encryption_errors": self.encryption_errors,
            "decryption_errors": self.decryption_errors,
            "last_packet_time": self.last_packet_time,
        }
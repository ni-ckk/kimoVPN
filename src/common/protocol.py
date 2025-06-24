"""
Protocol Definition Module

Defines the message protocol for client-server communication.
"""

import json
import struct
from enum import Enum
from typing import Any, Dict, Optional, Tuple
from pydantic import BaseModel, Field, ValidationError
import structlog

logger = structlog.get_logger()


class MessageType(str, Enum):
    """VPN protocol message types."""
    # authentication messages
    AUTH_REQUEST = "auth_request"
    AUTH_RESPONSE = "auth_response"
    
    # connection control
    CONNECT = "connect"
    DISCONNECT = "disconnect"
    HEARTBEAT = "heartbeat"
    
    # data transfer
    DATA = "data"
    
    # error messages
    ERROR = "error"
    
    # status messages
    STATUS = "status"


class ProtocolMessage(BaseModel):
    """Base protocol message structure."""
    msg_type: MessageType = Field(..., description="Type of the message")
    sequence: int = Field(default=0, ge=0, description="Message sequence number")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Message payload")


class MessageEncoder:
    """Encodes messages for network transmission."""
    
    @staticmethod
    def encode(message: ProtocolMessage) -> bytes:
        """
        Encode a protocol message to bytes.
        
        Format: [4 bytes length][json data]
        
        Args:
            message: Protocol message to encode
            
        Returns:
            Encoded message bytes
        """
        try:
            # convert message to json
            json_data = message.model_dump_json()
            json_bytes = json_data.encode('utf-8')
            
            # prepend length header (4 bytes, big endian)
            length = len(json_bytes)
            if length > 0xFFFFFFFF:
                raise ValueError(f"Message too large: {length} bytes")
            
            length_header = struct.pack('>I', length)
            
            return length_header + json_bytes
            
        except Exception as e:
            logger.error("failed to encode message", error=str(e))
            raise


class MessageDecoder:
    """Decodes messages from network transmission."""
    
    def __init__(self):
        """Initialize decoder with empty buffer."""
        self.buffer = b""
    
    def add_data(self, data: bytes):
        """
        Add received data to buffer.
        
        Args:
            data: Received bytes to add
        """
        self.buffer += data
    
    def get_message(self) -> Optional[ProtocolMessage]:
        """
        Try to extract a complete message from buffer.
        
        Returns:
            Decoded message if complete, None otherwise
        """
        # need at least 4 bytes for length header
        if len(self.buffer) < 4:
            return None
        
        # read length header
        length = struct.unpack('>I', self.buffer[:4])[0]
        
        # check if we have complete message
        if len(self.buffer) < 4 + length:
            return None
        
        try:
            # extract message data
            json_bytes = self.buffer[4:4+length]
            
            # remove message from buffer
            self.buffer = self.buffer[4+length:]
            
            # decode json
            json_data = json_bytes.decode('utf-8')
            message_dict = json.loads(json_data)
            
            # parse into protocol message
            message = ProtocolMessage(**message_dict)
            
            return message
            
        except (json.JSONDecodeError, ValidationError) as e:
            logger.error("failed to decode message", error=str(e))
            # remove corrupted data from buffer
            self.buffer = self.buffer[4+length:]
            raise
    
    def get_all_messages(self) -> list[ProtocolMessage]:
        """
        Extract all complete messages from buffer.
        
        Returns:
            List of decoded messages
        """
        messages = []
        while True:
            message = self.get_message()
            if message is None:
                break
            messages.append(message)
        return messages


def create_auth_request(username: str, password: str, sequence: int = 0) -> ProtocolMessage:
    """
    Create an authentication request message.
    
    Args:
        username: Username for authentication
        password: Password for authentication  
        sequence: Message sequence number
        
    Returns:
        Authentication request message
    """
    return ProtocolMessage(
        msg_type=MessageType.AUTH_REQUEST,
        sequence=sequence,
        payload={
            "username": username,
            "password": password,
            "version": "0.1.0"
        }
    )


def create_auth_response(
    success: bool, 
    message: str,
    virtual_ip: Optional[str] = None,
    session_token: Optional[str] = None,
    sequence: int = 0
) -> ProtocolMessage:
    """
    Create an authentication response message.
    
    Args:
        success: Whether authentication succeeded
        message: Response message
        virtual_ip: Assigned virtual IP (if successful)
        session_token: Session token (if successful)
        sequence: Message sequence number
        
    Returns:
        Authentication response message
    """
    payload = {
        "success": success,
        "message": message
    }
    
    if success and virtual_ip:
        payload["virtual_ip"] = virtual_ip
    if success and session_token:
        payload["session_token"] = session_token
    
    return ProtocolMessage(
        msg_type=MessageType.AUTH_RESPONSE,
        sequence=sequence,
        payload=payload
    )


def create_error_message(
    error_code: str,
    error_message: str,
    details: Optional[Dict[str, Any]] = None,
    sequence: int = 0
) -> ProtocolMessage:
    """
    Create an error message.
    
    Args:
        error_code: Error code identifier
        error_message: Human-readable error message
        details: Optional error details
        sequence: Message sequence number
        
    Returns:
        Error message
    """
    payload = {
        "error_code": error_code,
        "error_message": error_message
    }
    
    if details:
        payload["details"] = details
    
    return ProtocolMessage(
        msg_type=MessageType.ERROR,
        sequence=sequence,
        payload=payload
    )


def create_heartbeat_message(sequence: int = 0) -> ProtocolMessage:
    """
    Create a heartbeat message.
    
    Args:
        sequence: Message sequence number
        
    Returns:
        Heartbeat message
    """
    return ProtocolMessage(
        msg_type=MessageType.HEARTBEAT,
        sequence=sequence,
        payload={"timestamp": "now"}
    )
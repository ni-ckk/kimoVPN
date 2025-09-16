"""
Common Data Models

Pydantic models used across client and server.
"""

from typing import Optional, List
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field
from decimal import Decimal


class ConnectionStatus(str, Enum):
    """VPN connection status enumeration."""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    AUTHENTICATING = "authenticating"
    CONNECTED = "connected"
    DISCONNECTING = "disconnecting"
    ERROR = "error"


class AuthRequest(BaseModel):
    """Authentication request model."""
    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=8, max_length=100)
    client_version: str = Field(default="0.1.0")


class AuthResponse(BaseModel):
    """Authentication response model."""
    success: bool
    message: str
    virtual_ip: Optional[str] = None
    session_token: Optional[str] = None


class PacketHeader(BaseModel):
    """VPN packet header structure."""
    sequence: int
    timestamp: datetime
    packet_type: str
    payload_size: int


class ConnectionStats(BaseModel):
    """Connection statistics model."""
    status: ConnectionStatus
    connected_since: Optional[datetime] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    current_latency_ms: Optional[float] = None
    average_latency_ms: Optional[float] = None
    
    
class ServerInfo(BaseModel):
    """Server information model."""
    server_version: str
    max_clients: int
    current_clients: int
    virtual_network: str
    uptime_seconds: int


class ErrorResponse(BaseModel):
    """Error response model."""
    error_code: str
    error_message: str
    details: Optional[dict] = None
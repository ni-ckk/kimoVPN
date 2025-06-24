"""
VPN Connection Module

Handles the core VPN client connection logic including:
- TCP/TLS connection to server
- Authentication flow
- Packet handling
"""

import socket
import ssl
import time
import threading
from typing import Optional, Tuple
from pydantic import BaseModel
import structlog
import sys
import os

# add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.common.protocol import (
    MessageDecoder, MessageEncoder, ProtocolMessage, MessageType,
    create_auth_request, create_heartbeat_message
)
from src.common.crypto import create_client_ssl_context
from src.common.models import ConnectionStatus

logger = structlog.get_logger()


class ConnectionConfig(BaseModel):
    """Configuration for VPN connection."""
    server_host: str
    server_port: int
    username: str
    password: str
    ssl_verify: bool = True
    ca_cert_path: Optional[str] = None
    client_cert_path: Optional[str] = None
    client_key_path: Optional[str] = None
    connection_timeout: int = 30
    retry_attempts: int = 3
    heartbeat_interval: int = 30


class VPNConnection:
    """Manages VPN connection to server."""
    
    def __init__(self, config: ConnectionConfig):
        """
        Initialize VPN connection.
        
        Args:
            config: Connection configuration
        """
        self.config = config
        self.socket: Optional[socket.socket] = None
        self.ssl_socket: Optional[ssl.SSLSocket] = None
        self.ssl_context: Optional[ssl.SSLContext] = None
        self.connected = False
        self.authenticated = False
        self.status = ConnectionStatus.DISCONNECTED
        self.session_token: Optional[str] = None
        self.virtual_ip: Optional[str] = None
        
        self.decoder = MessageDecoder()
        self.encoder = MessageEncoder()
        self.sequence = 0
        self.last_activity = time.time()
        
        self.receive_thread: Optional[threading.Thread] = None
        self.heartbeat_thread: Optional[threading.Thread] = None
        self.running = False
        self.lock = threading.Lock()
        
        # callbacks
        self.on_status_change = None
        self.on_message_received = None
        
    def connect(self) -> bool:
        """
        Establish connection to VPN server.
        
        Returns:
            True if connection successful, False otherwise
        """
        logger.info(
            "connecting to vpn server",
            server=f"{self.config.server_host}:{self.config.server_port}"
        )
        
        self._update_status(ConnectionStatus.CONNECTING)
        
        # retry logic with exponential backoff
        retry_delay = 1
        for attempt in range(self.config.retry_attempts):
            try:
                if attempt > 0:
                    logger.info(f"retry attempt {attempt + 1}/{self.config.retry_attempts}")
                    time.sleep(retry_delay)
                    retry_delay *= 2  # exponential backoff
                
                # create socket
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(self.config.connection_timeout)
                
                # connect to server
                logger.debug(f"connecting to {self.config.server_host}:{self.config.server_port}")
                self.socket.connect((self.config.server_host, self.config.server_port))
                
                # create ssl context
                self.ssl_context, server_hostname = create_client_ssl_context(
                    ca_cert_path=self.config.ca_cert_path,
                    client_cert_path=self.config.client_cert_path,
                    client_key_path=self.config.client_key_path,
                    verify_server=self.config.ssl_verify,
                    server_hostname=self.config.server_host
                )
                
                # wrap with ssl
                logger.debug("performing ssl handshake")
                self.ssl_socket = self.ssl_context.wrap_socket(
                    self.socket,
                    server_hostname=server_hostname,
                    do_handshake_on_connect=True,
                    suppress_ragged_eofs=True
                )
                
                self.connected = True
                self.running = True
                
                # start receive thread
                self.receive_thread = threading.Thread(
                    target=self._receive_loop,
                    daemon=True
                )
                self.receive_thread.start()
                
                # start heartbeat thread  
                self.heartbeat_thread = threading.Thread(
                    target=self._heartbeat_loop,
                    daemon=True
                )
                self.heartbeat_thread.start()
                
                logger.info("connection established")
                
                # now authenticate
                return self.authenticate()
                
            except (socket.timeout, socket.error) as e:
                logger.warning(f"connection attempt {attempt + 1} failed: {e}")
                self._cleanup_connection()
                
            except ssl.SSLError as e:
                logger.error(f"ssl error: {e}")
                self._cleanup_connection()
                break  # don't retry ssl errors
                
            except Exception as e:
                logger.error(f"unexpected error: {e}")
                self._cleanup_connection()
                break
        
        self._update_status(ConnectionStatus.ERROR)
        return False
    
    def authenticate(self) -> bool:
        """
        Authenticate with VPN server.
        
        Returns:
            True if authentication successful, False otherwise
        """
        if not self.connected:
            logger.error("cannot authenticate - not connected")
            return False
        
        logger.info("authenticating with vpn server")
        self._update_status(ConnectionStatus.AUTHENTICATING)
        
        # create auth request
        auth_msg = create_auth_request(
            username=self.config.username,
            password=self.config.password,
            sequence=self._get_sequence()
        )
        
        # send auth request
        if not self._send_message(auth_msg):
            logger.error("failed to send auth request")
            self._update_status(ConnectionStatus.ERROR)
            return False
        
        # wait for auth response (with timeout)
        start_time = time.time()
        timeout = 10  # 10 seconds for auth response
        
        while time.time() - start_time < timeout:
            if self.authenticated:
                self._update_status(ConnectionStatus.CONNECTED)
                logger.info(
                    "authentication successful",
                    username=self.config.username,
                    virtual_ip=self.virtual_ip
                )
                return True
            
            if self.status == ConnectionStatus.ERROR:
                logger.error("authentication failed")
                return False
            
            time.sleep(0.1)
        
        logger.error("authentication timeout")
        self._update_status(ConnectionStatus.ERROR)
        return False
    
    def disconnect(self):
        """Disconnect from VPN server."""
        logger.info("disconnecting from vpn server")
        self._update_status(ConnectionStatus.DISCONNECTING)
        
        # send disconnect message if connected
        if self.connected and self.ssl_socket:
            try:
                disconnect_msg = ProtocolMessage(
                    msg_type=MessageType.DISCONNECT,
                    sequence=self._get_sequence()
                )
                self._send_message(disconnect_msg)
            except:
                pass
        
        # stop threads
        self.running = False
        
        # cleanup connection
        self._cleanup_connection()
        
        self.authenticated = False
        self.session_token = None
        self.virtual_ip = None
        
        self._update_status(ConnectionStatus.DISCONNECTED)
        logger.info("disconnected from vpn server")
    
    def _send_message(self, message: ProtocolMessage) -> bool:
        """
        Send a protocol message to server.
        
        Args:
            message: Message to send
            
        Returns:
            True if sent successfully
        """
        try:
            with self.lock:
                if not self.ssl_socket:
                    return False
                
                data = self.encoder.encode(message)
                self.ssl_socket.sendall(data)
                self.last_activity = time.time()
                
                logger.debug(f"sent message: {message.msg_type}")
                return True
                
        except Exception as e:
            logger.error(f"failed to send message: {e}")
            return False
    
    def _receive_loop(self):
        """Receive messages from server."""
        logger.debug("receive loop started")
        
        try:
            while self.running and self.ssl_socket:
                try:
                    # receive data with timeout
                    self.ssl_socket.settimeout(1.0)
                    data = self.ssl_socket.recv(4096)
                    
                    if not data:
                        logger.info("server disconnected")
                        break
                    
                    # add to decoder
                    self.decoder.add_data(data)
                    
                    # process messages
                    messages = self.decoder.get_all_messages()
                    for message in messages:
                        self._process_message(message)
                    
                except socket.timeout:
                    # check for timeout
                    if time.time() - self.last_activity > 90:  # 90 second timeout
                        logger.warning("connection timeout")
                        break
                    
                except ssl.SSLError as e:
                    logger.error(f"ssl error in receive: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"receive loop error: {e}")
            
        finally:
            logger.debug("receive loop stopped")
            if self.running:
                self.running = False
                self._update_status(ConnectionStatus.ERROR)
    
    def _process_message(self, message: ProtocolMessage):
        """
        Process received message from server.
        
        Args:
            message: Received message
        """
        self.last_activity = time.time()
        
        logger.debug(f"received message: {message.msg_type}")
        
        if message.msg_type == MessageType.AUTH_RESPONSE:
            self._handle_auth_response(message)
        elif message.msg_type == MessageType.HEARTBEAT:
            # respond with heartbeat
            response = create_heartbeat_message(sequence=message.sequence)
            self._send_message(response)
        elif message.msg_type == MessageType.ERROR:
            logger.error(
                "server error",
                error_code=message.payload.get("error_code"),
                error_message=message.payload.get("error_message")
            )
            self._update_status(ConnectionStatus.ERROR)
        else:
            # notify callback if set
            if self.on_message_received:
                self.on_message_received(message)
    
    def _handle_auth_response(self, message: ProtocolMessage):
        """
        Handle authentication response.
        
        Args:
            message: Auth response message
        """
        success = message.payload.get("success", False)
        auth_message = message.payload.get("message", "")
        
        if success:
            self.authenticated = True
            self.session_token = message.payload.get("session_token")
            self.virtual_ip = message.payload.get("virtual_ip")
            
            logger.info(
                "authentication successful",
                message=auth_message,
                virtual_ip=self.virtual_ip
            )
        else:
            logger.error(f"authentication failed: {auth_message}")
            self._update_status(ConnectionStatus.ERROR)
    
    def _heartbeat_loop(self):
        """Send periodic heartbeats to server."""
        logger.debug("heartbeat loop started")
        
        while self.running:
            time.sleep(self.config.heartbeat_interval)
            
            if self.authenticated:
                heartbeat = create_heartbeat_message(sequence=self._get_sequence())
                self._send_message(heartbeat)
        
        logger.debug("heartbeat loop stopped")
    
    def _cleanup_connection(self):
        """Cleanup socket connections."""
        if self.ssl_socket:
            try:
                self.ssl_socket.close()
            except:
                pass
            self.ssl_socket = None
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
        
        self.connected = False
    
    def _update_status(self, status: ConnectionStatus):
        """
        Update connection status.
        
        Args:
            status: New status
        """
        old_status = self.status
        self.status = status
        
        if old_status != status:
            logger.info(f"status changed: {old_status} -> {status}")
            
            # notify callback if set
            if self.on_status_change:
                self.on_status_change(status)
    
    def _get_sequence(self) -> int:
        """
        Get next sequence number.
        
        Returns:
            Next sequence number
        """
        with self.lock:
            seq = self.sequence
            self.sequence += 1
            return seq
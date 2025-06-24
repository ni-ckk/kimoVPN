"""
VPN Server Module

Handles the core VPN server functionality including:
- TCP/TLS server socket
- Client connection management
- Authentication
- Packet routing
"""

import socket
import ssl
import threading
import time
from typing import Dict, Optional, Tuple
from pydantic import BaseModel
import structlog
import sys
import os

# add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.server.auth import AuthManager
from src.common.protocol import (
    MessageDecoder, MessageEncoder, ProtocolMessage, MessageType,
    create_auth_response, create_error_message, create_heartbeat_message
)
from src.common.crypto import create_server_ssl_context, generate_session_token

logger = structlog.get_logger()


class ServerConfig(BaseModel):
    """Configuration for VPN server."""
    bind_host: str = "0.0.0.0"
    bind_port: int = 13337
    max_clients: int = 10
    ssl_cert_path: str
    ssl_key_path: str
    ca_cert_path: Optional[str] = None
    require_client_cert: bool = False
    virtual_network: str = "10.8.0.0/24"
    heartbeat_interval: int = 30
    client_timeout: int = 90


class ClientConnection:
    """Represents a connected VPN client."""
    
    def __init__(self, client_socket: ssl.SSLSocket, address: tuple):
        """
        Initialize client connection.
        
        Args:
            client_socket: SSL wrapped client socket
            address: Client address tuple (ip, port)
        """
        self.socket = client_socket
        self.address = address
        self.authenticated = False
        self.username: Optional[str] = None
        self.virtual_ip: Optional[str] = None
        self.session_token: Optional[str] = None
        self.decoder = MessageDecoder()
        self.encoder = MessageEncoder()
        self.last_activity = time.time()
        self.sequence = 0
        self.running = True
        self.lock = threading.Lock()
    
    def send_message(self, message: ProtocolMessage) -> bool:
        """
        Send a protocol message to client.
        
        Args:
            message: Message to send
            
        Returns:
            True if sent successfully
        """
        try:
            with self.lock:
                data = self.encoder.encode(message)
                self.socket.sendall(data)
                self.last_activity = time.time()
                return True
        except Exception as e:
            logger.error("failed to send message", error=str(e), address=self.address)
            return False
    
    def close(self):
        """Close the client connection."""
        self.running = False
        try:
            self.socket.close()
        except:
            pass


class VPNServer:
    """Main VPN server class."""
    
    def __init__(self, config: ServerConfig, auth_manager: Optional[AuthManager] = None):
        """
        Initialize VPN server.
        
        Args:
            config: Server configuration
            auth_manager: Optional authentication manager
        """
        self.config = config
        self.server_socket: Optional[socket.socket] = None
        self.ssl_context: Optional[ssl.SSLContext] = None
        self.clients: Dict[str, ClientConnection] = {}
        self.running = False
        self.accept_thread: Optional[threading.Thread] = None
        self.heartbeat_thread: Optional[threading.Thread] = None
        self.auth_manager = auth_manager or AuthManager()
        self.next_virtual_ip = 2  # start from 10.8.0.2
        self.lock = threading.Lock()
    
    def start(self):
        """Start the VPN server."""
        try:
            # create ssl context
            self.ssl_context = create_server_ssl_context(
                cert_path=self.config.ssl_cert_path,
                key_path=self.config.ssl_key_path,
                ca_cert_path=self.config.ca_cert_path,
                require_client_cert=self.config.require_client_cert
            )
            
            # create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.config.bind_host, self.config.bind_port))
            self.server_socket.listen(self.config.max_clients)
            
            self.running = True
            
            # start accept thread
            self.accept_thread = threading.Thread(target=self._accept_clients, daemon=True)
            self.accept_thread.start()
            
            # start heartbeat thread
            self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
            self.heartbeat_thread.start()
            
            logger.info(
                "vpn server started",
                bind=f"{self.config.bind_host}:{self.config.bind_port}",
                max_clients=self.config.max_clients
            )
            
        except Exception as e:
            logger.error("failed to start server", error=str(e))
            self.stop()
            raise
    
    def stop(self):
        """Stop the VPN server."""
        logger.info("stopping vpn server")
        self.running = False
        
        # close all client connections
        with self.lock:
            for client_id, client in list(self.clients.items()):
                client.close()
            self.clients.clear()
        
        # close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        logger.info("vpn server stopped")
    
    def _accept_clients(self):
        """Accept incoming client connections."""
        while self.running:
            try:
                # accept connection
                client_socket, address = self.server_socket.accept()
                
                # check max clients
                if len(self.clients) >= self.config.max_clients:
                    logger.warning("max clients reached, rejecting connection", address=address)
                    client_socket.close()
                    continue
                
                # wrap with ssl
                try:
                    ssl_socket = self.ssl_context.wrap_socket(
                        client_socket,
                        server_side=True,
                        do_handshake_on_connect=True,
                        suppress_ragged_eofs=True
                    )
                except ssl.SSLError as e:
                    logger.error("ssl handshake failed", error=str(e), address=address)
                    client_socket.close()
                    continue
                
                # create client connection
                client = ClientConnection(ssl_socket, address)
                client_id = f"{address[0]}:{address[1]}"
                
                with self.lock:
                    self.clients[client_id] = client
                
                # start client handler thread
                thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_id, client),
                    daemon=True
                )
                thread.start()
                
                logger.info("client connected", address=address)
                
            except Exception as e:
                if self.running:
                    logger.error("error accepting client", error=str(e))
    
    def _handle_client(self, client_id: str, client: ClientConnection):
        """
        Handle individual client connection.
        
        Args:
            client_id: Client identifier
            client: Client connection object
        """
        try:
            while client.running and self.running:
                # receive data with timeout
                client.socket.settimeout(1.0)
                
                try:
                    data = client.socket.recv(4096)
                    if not data:
                        logger.info("client disconnected", address=client.address)
                        break
                    
                    # add data to decoder
                    client.decoder.add_data(data)
                    
                    # process all complete messages
                    messages = client.decoder.get_all_messages()
                    for message in messages:
                        self._process_message(client, message)
                    
                except socket.timeout:
                    # check for client timeout
                    if time.time() - client.last_activity > self.config.client_timeout:
                        logger.warning("client timed out", address=client.address)
                        break
                    
                except ssl.SSLError as e:
                    logger.error("ssl error", error=str(e), address=client.address)
                    break
                    
        except Exception as e:
            logger.error("client handler error", error=str(e), address=client.address)
            
        finally:
            # cleanup
            with self.lock:
                if client.session_token:
                    self.auth_manager.remove_session(client.session_token)
                self.clients.pop(client_id, None)
            
            client.close()
            logger.info("client handler stopped", address=client.address)
    
    def _process_message(self, client: ClientConnection, message: ProtocolMessage):
        """
        Process received message from client.
        
        Args:
            client: Client connection
            message: Received message
        """
        client.last_activity = time.time()
        
        logger.debug(
            "received message",
            msg_type=message.msg_type,
            address=client.address
        )
        
        if message.msg_type == MessageType.AUTH_REQUEST:
            self._handle_auth_request(client, message)
        elif message.msg_type == MessageType.HEARTBEAT:
            # respond with heartbeat
            response = create_heartbeat_message(sequence=message.sequence)
            client.send_message(response)
        elif message.msg_type == MessageType.DISCONNECT:
            logger.info("client requested disconnect", address=client.address)
            client.running = False
        else:
            # check if authenticated for other message types
            if not client.authenticated:
                error_msg = create_error_message(
                    error_code="AUTH_REQUIRED",
                    error_message="Authentication required",
                    sequence=message.sequence
                )
                client.send_message(error_msg)
                return
            
            # handle other message types (future phases)
            logger.info(
                "unhandled message type",
                msg_type=message.msg_type,
                address=client.address
            )
    
    def _handle_auth_request(self, client: ClientConnection, message: ProtocolMessage):
        """
        Handle authentication request.
        
        Args:
            client: Client connection
            message: Auth request message
        """
        username = message.payload.get("username")
        password = message.payload.get("password")
        
        if not username or not password:
            response = create_auth_response(
                success=False,
                message="Username and password required",
                sequence=message.sequence
            )
            client.send_message(response)
            return
        
        # authenticate
        success, auth_message = self.auth_manager.authenticate(
            username=username,
            password=password,
            ip_address=client.address[0]
        )
        
        if success:
            # generate session token and virtual ip
            session_token = generate_session_token()
            virtual_ip = self._allocate_virtual_ip()
            
            # update client state
            client.authenticated = True
            client.username = username
            client.session_token = session_token
            client.virtual_ip = virtual_ip
            
            # register session
            self.auth_manager.create_session(username, session_token)
            
            # send success response
            response = create_auth_response(
                success=True,
                message=auth_message,
                virtual_ip=virtual_ip,
                session_token=session_token,
                sequence=message.sequence
            )
            
            logger.info(
                "client authenticated",
                username=username,
                virtual_ip=virtual_ip,
                address=client.address
            )
        else:
            # send failure response
            response = create_auth_response(
                success=False,
                message=auth_message,
                sequence=message.sequence
            )
            
            logger.warning(
                "authentication failed",
                username=username,
                reason=auth_message,
                address=client.address
            )
        
        client.send_message(response)
    
    def _allocate_virtual_ip(self) -> str:
        """
        Allocate a virtual IP address for client.
        
        Returns:
            Allocated virtual IP
        """
        # simple allocation from pool (phase 1)
        # in production, would track allocated ips properly
        with self.lock:
            virtual_ip = f"10.8.0.{self.next_virtual_ip}"
            self.next_virtual_ip += 1
            if self.next_virtual_ip > 254:
                self.next_virtual_ip = 2  # wrap around
            return virtual_ip
    
    def _heartbeat_loop(self):
        """Send periodic heartbeats to all connected clients."""
        while self.running:
            time.sleep(self.config.heartbeat_interval)
            
            with self.lock:
                for client in list(self.clients.values()):
                    if client.authenticated:
                        heartbeat = create_heartbeat_message(sequence=client.sequence)
                        client.sequence += 1
                        client.send_message(heartbeat)
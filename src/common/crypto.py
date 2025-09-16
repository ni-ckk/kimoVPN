"""
Cryptographic Utilities Module

Provides SSL context creation and encryption utilities.
"""

import ssl
import os
from pathlib import Path
from typing import Optional, Tuple
import structlog

logger = structlog.get_logger()


def create_server_ssl_context(
    cert_path: str,
    key_path: str,
    ca_cert_path: Optional[str] = None,
    require_client_cert: bool = False
) -> ssl.SSLContext:
    """
    Create SSL context for server.
    
    Args:
        cert_path: Path to server certificate
        key_path: Path to server private key
        ca_cert_path: Optional path to CA certificate
        require_client_cert: Whether to require client certificate
        
    Returns:
        Configured SSL context
        
    Raises:
        FileNotFoundError: If certificate files not found
        ssl.SSLError: If certificates are invalid
    """
    # validate certificate paths
    if not Path(cert_path).exists():
        raise FileNotFoundError(f"Server certificate not found: {cert_path}")
    if not Path(key_path).exists():
        raise FileNotFoundError(f"Server key not found: {key_path}")
    
    # create ssl context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    
    # load server certificate and key
    context.load_cert_chain(cert_path, key_path)
    
    # configure client certificate verification
    if require_client_cert:
        context.verify_mode = ssl.CERT_REQUIRED
        if ca_cert_path and Path(ca_cert_path).exists():
            context.load_verify_locations(ca_cert_path)
    else:
        context.verify_mode = ssl.CERT_NONE
    
    # set secure options
    context.options |= ssl.OP_NO_SSLv2
    context.options |= ssl.OP_NO_SSLv3
    context.options |= ssl.OP_NO_TLSv1
    context.options |= ssl.OP_NO_TLSv1_1
    
    # set ciphers to strong ones only
    context.set_ciphers('HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA')
    
    logger.info(
        "created server ssl context",
        cert_path=cert_path,
        require_client_cert=require_client_cert
    )
    
    return context


def create_client_ssl_context(
    ca_cert_path: Optional[str] = None,
    client_cert_path: Optional[str] = None,
    client_key_path: Optional[str] = None,
    verify_server: bool = True,
    server_hostname: Optional[str] = None
) -> Tuple[ssl.SSLContext, Optional[str]]:
    """
    Create SSL context for client.
    
    Args:
        ca_cert_path: Optional path to CA certificate
        client_cert_path: Optional path to client certificate
        client_key_path: Optional path to client private key
        verify_server: Whether to verify server certificate
        server_hostname: Expected server hostname for verification
        
    Returns:
        Tuple of (SSL context, server hostname for verification)
        
    Raises:
        FileNotFoundError: If certificate files not found
    """
    # create ssl context
    if verify_server:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        
        # load ca certificate if provided
        if ca_cert_path and Path(ca_cert_path).exists():
            context.load_verify_locations(ca_cert_path)
        
        # set server hostname for verification
        check_hostname = server_hostname or "localhost"
    else:
        # create context without verification for testing
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        check_hostname = None
        
        logger.warning("ssl verification disabled - use only for testing")
    
    # load client certificate if provided (for mutual tls)
    if client_cert_path and client_key_path:
        if not Path(client_cert_path).exists():
            raise FileNotFoundError(f"Client certificate not found: {client_cert_path}")
        if not Path(client_key_path).exists():
            raise FileNotFoundError(f"Client key not found: {client_key_path}")
        
        context.load_cert_chain(client_cert_path, client_key_path)
        logger.info("loaded client certificate for mutual tls")
    
    # set secure options
    context.options |= ssl.OP_NO_SSLv2
    context.options |= ssl.OP_NO_SSLv3
    context.options |= ssl.OP_NO_TLSv1
    context.options |= ssl.OP_NO_TLSv1_1
    
    logger.info(
        "created client ssl context",
        verify_server=verify_server,
        has_client_cert=(client_cert_path is not None)
    )
    
    return context, check_hostname


def generate_session_token(length: int = 32) -> str:
    """
    Generate a secure random session token.
    
    Args:
        length: Length of token in bytes
        
    Returns:
        Hex-encoded session token
    """
    return os.urandom(length).hex()


def verify_session_token(token: str, expected_length: int = 32) -> bool:
    """
    Verify session token format.
    
    Args:
        token: Token to verify
        expected_length: Expected length in bytes
        
    Returns:
        True if token is valid format
    """
    try:
        # check if valid hex
        bytes.fromhex(token)
        # check length (hex string is 2x byte length)
        return len(token) == expected_length * 2
    except (ValueError, TypeError):
        return False
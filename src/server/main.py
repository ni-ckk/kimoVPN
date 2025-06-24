#!/usr/bin/env python
"""
VPN Server Main Entry Point

Starts the VPN server with command-line arguments and proper configuration.
"""

import sys
import os
import signal
import argparse
from pathlib import Path
from typing import Optional

# add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.server.server import VPNServer, ServerConfig
from src.server.auth import AuthManager
from src.common.logging import configure_logging
import structlog

# global server instance for signal handling
server_instance: Optional[VPNServer] = None


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    logger = structlog.get_logger()
    logger.info(f"received signal {signum}, shutting down")
    
    if server_instance:
        server_instance.stop()
    
    sys.exit(0)


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="kimoVPN Server - Secure VPN Server Application"
    )
    
    # network settings
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind server to (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=13337,
        help="Port to bind server to (default: 13337)"
    )
    
    # ssl settings
    parser.add_argument(
        "--cert",
        default="certs/server.crt",
        help="Path to SSL certificate (default: certs/server.crt)"
    )
    parser.add_argument(
        "--key",
        default="certs/server.key",
        help="Path to SSL private key (default: certs/server.key)"
    )
    parser.add_argument(
        "--ca-cert",
        default="certs/ca.crt",
        help="Path to CA certificate (default: certs/ca.crt)"
    )
    parser.add_argument(
        "--require-client-cert",
        action="store_true",
        help="Require client certificate for connection"
    )
    
    # server settings
    parser.add_argument(
        "--max-clients",
        type=int,
        default=10,
        help="Maximum number of concurrent clients (default: 10)"
    )
    parser.add_argument(
        "--virtual-network",
        default="10.8.0.0/24",
        help="Virtual network for VPN (default: 10.8.0.0/24)"
    )
    
    # authentication settings
    parser.add_argument(
        "--users-file",
        default="data/users.json",
        help="Path to users database file (default: data/users.json)"
    )
    parser.add_argument(
        "--max-auth-attempts",
        type=int,
        default=5,
        help="Max authentication attempts per window (default: 5)"
    )
    parser.add_argument(
        "--auth-window",
        type=int,
        default=300,
        help="Authentication rate limit window in seconds (default: 300)"
    )
    
    # logging settings
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)"
    )
    parser.add_argument(
        "--log-file",
        help="Optional log file path"
    )
    
    return parser.parse_args()


def main():
    """Main server entry point."""
    global server_instance
    
    # parse arguments
    args = parse_arguments()
    
    # configure logging
    configure_logging(
        log_level=args.log_level,
        log_file=args.log_file,
        service_name="kimovpn-server"
    )
    
    logger = structlog.get_logger()
    logger.info("kimoVPN server starting", version="0.1.0")
    
    # register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    if sys.platform == "win32":
        signal.signal(signal.SIGBREAK, signal_handler)  # windows ctrl+break
    
    try:
        # verify certificate files exist
        cert_path = Path(args.cert)
        key_path = Path(args.key)
        
        if not cert_path.exists():
            logger.error(f"certificate file not found: {cert_path}")
            logger.info("run 'python scripts/generate_certs.py' to generate certificates")
            sys.exit(1)
        
        if not key_path.exists():
            logger.error(f"key file not found: {key_path}")
            logger.info("run 'python scripts/generate_certs.py' to generate certificates")
            sys.exit(1)
        
        # create auth manager
        auth_manager = AuthManager(
            users_file=args.users_file,
            max_attempts=args.max_auth_attempts,
            window_seconds=args.auth_window
        )
        
        # create server configuration
        config = ServerConfig(
            bind_host=args.host,
            bind_port=args.port,
            max_clients=args.max_clients,
            ssl_cert_path=str(cert_path),
            ssl_key_path=str(key_path),
            ca_cert_path=str(Path(args.ca_cert)) if Path(args.ca_cert).exists() else None,
            require_client_cert=args.require_client_cert,
            virtual_network=args.virtual_network
        )
        
        # create and start server
        server_instance = VPNServer(config, auth_manager)
        server_instance.start()
        
        logger.info(
            "server ready",
            host=args.host,
            port=args.port,
            max_clients=args.max_clients
        )
        
        print("\n" + "=" * 50)
        print("kimoVPN Server Running")
        print("=" * 50)
        print(f"Address: {args.host}:{args.port}")
        print(f"Max Clients: {args.max_clients}")
        print(f"Virtual Network: {args.virtual_network}")
        print("\nDefault test credentials:")
        print("  Username: testuser")
        print("  Password: testpass123")
        print("\nPress Ctrl+C to stop the server")
        print("=" * 50 + "\n")
        
        # keep server running
        while server_instance.running:
            try:
                signal.pause() if hasattr(signal, 'pause') else input()
            except (KeyboardInterrupt, EOFError):
                break
        
    except Exception as e:
        logger.error(f"server error: {e}", exc_info=True)
        if server_instance:
            server_instance.stop()
        sys.exit(1)
    
    finally:
        if server_instance:
            server_instance.stop()
        logger.info("server shutdown complete")


if __name__ == "__main__":
    main()
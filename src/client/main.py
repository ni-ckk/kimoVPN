#!/usr/bin/env python
"""
VPN Client Main Entry Point

Starts the VPN client with web UI and command-line interface.
"""

import sys
import os
import signal
import time
import argparse
import threading
import webbrowser
from pathlib import Path
from typing import Optional

# add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.client.connection import VPNConnection, ConnectionConfig
from src.client.config import get_settings
from src.client.web_ui.app import run_web_ui, vpn_connection, connection_status
from src.common.logging import configure_logging
from src.common.models import ConnectionStatus
import structlog

# global connection instance for signal handling
connection_instance: Optional[VPNConnection] = None
web_thread: Optional[threading.Thread] = None


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    logger = structlog.get_logger()
    logger.info(f"received signal {signum}, shutting down")
    
    if connection_instance:
        connection_instance.disconnect()
    
    sys.exit(0)


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="kimoVPN Client - Secure VPN Client Application"
    )
    
    # connection settings
    parser.add_argument(
        "--server",
        help="VPN server address (overrides config)"
    )
    parser.add_argument(
        "--port",
        type=int,
        help="VPN server port (overrides config)"
    )
    parser.add_argument(
        "--username",
        help="Username for authentication (overrides config)"
    )
    parser.add_argument(
        "--password",
        help="Password for authentication (overrides config)"
    )
    
    # ssl settings
    parser.add_argument(
        "--ca-cert",
        default="certs/ca.crt",
        help="Path to CA certificate (default: certs/ca.crt)"
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Disable SSL certificate verification (for testing)"
    )
    
    # ui settings
    parser.add_argument(
        "--no-ui",
        action="store_true",
        help="Run without web UI (command-line only)"
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Don't auto-launch browser for web UI"
    )
    parser.add_argument(
        "--ui-host",
        default="127.0.0.1",
        help="Web UI host (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--ui-port",
        type=int,
        default=5000,
        help="Web UI port (default: 5000)"
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
    
    # command mode
    parser.add_argument(
        "--connect",
        action="store_true",
        help="Connect immediately (command-line mode)"
    )
    
    # local development mode
    parser.add_argument(
        "--local",
        action="store_true",
        help="Local development mode (disables SSL verification, uses localhost)"
    )
    
    return parser.parse_args()


def run_cli_mode(connection: VPNConnection):
    """
    Run in command-line mode without web UI.
    
    Args:
        connection: VPN connection instance
    """
    logger = structlog.get_logger()
    
    print("\n" + "=" * 50)
    print("kimoVPN Client - Command Line Mode")
    print("=" * 50)
    print("Commands:")
    print("  connect  - Connect to VPN server")
    print("  disconnect - Disconnect from VPN")
    print("  status   - Show connection status")
    print("  quit     - Exit the application")
    print("=" * 50 + "\n")
    
    while True:
        try:
            command = input("> ").strip().lower()
            
            if command == "connect":
                if connection.status != ConnectionStatus.DISCONNECTED:
                    print("Already connected or connecting")
                else:
                    print("Connecting...")
                    if connection.connect():
                        print(f"Connected successfully!")
                        print(f"Virtual IP: {connection.virtual_ip}")
                    else:
                        print("Connection failed")
            
            elif command == "disconnect":
                if connection.status in [ConnectionStatus.CONNECTED, ConnectionStatus.CONNECTING]:
                    print("Disconnecting...")
                    connection.disconnect()
                    print("Disconnected")
                else:
                    print("Not connected")
            
            elif command == "status":
                print(f"Status: {connection.status.value}")
                if connection.authenticated:
                    print(f"Username: {connection.config.username}")
                    print(f"Virtual IP: {connection.virtual_ip}")
                    print(f"Server: {connection.config.server_host}:{connection.config.server_port}")
            
            elif command in ["quit", "exit"]:
                if connection.status != ConnectionStatus.DISCONNECTED:
                    connection.disconnect()
                break
            
            else:
                print("Unknown command. Type 'help' for available commands.")
                
        except (KeyboardInterrupt, EOFError):
            print("\nExiting...")
            break
        except Exception as e:
            logger.error(f"cli error: {e}")


def main():
    """Main client entry point."""
    global connection_instance, web_thread, vpn_connection
    
    # parse arguments
    args = parse_arguments()
    
    # configure logging
    configure_logging(
        log_level=args.log_level,
        log_file=args.log_file,
        service_name="kimovpn-client"
    )
    
    logger = structlog.get_logger()
    logger.info("kimoVPN client starting", version="0.1.0")
    
    # register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    if sys.platform == "win32":
        signal.signal(signal.SIGBREAK, signal_handler)
    
    try:
        # get settings
        settings = get_settings()
        
        # handle local development mode
        if args.local:
            logger.info("local development mode enabled")
            args.no_verify = True  # disable ssl verification
            if not args.server:
                args.server = "127.0.0.1"  # use localhost
            if not args.username:
                args.username = "testuser"  # use test username
            if not args.password:
                args.password = "testpass123"  # use test password
        
        # override settings with command-line arguments
        server_host = args.server or settings.SERVER_HOST
        server_port = args.port or settings.SERVER_PORT
        username = args.username or settings.VPN_USERNAME
        password = args.password or settings.VPN_PASSWORD
        
        # check credentials
        if not username or not password:
            logger.error("username and password required")
            print("\nError: Username and password are required.")
            print("Set them in .env file or provide via command-line arguments.")
            print("Example: --username testuser --password testpass123")
            sys.exit(1)
        
        # verify ca certificate if ssl verification enabled
        ca_cert_path = Path(args.ca_cert) if not args.no_verify else None
        if ca_cert_path and not ca_cert_path.exists():
            logger.warning(f"ca certificate not found: {ca_cert_path}")
            logger.info("ssl verification will use system certificates")
            ca_cert_path = None
        
        # create connection configuration
        config = ConnectionConfig(
            server_host=server_host,
            server_port=server_port,
            username=username,
            password=password,
            ssl_verify=not args.no_verify,
            ca_cert_path=str(ca_cert_path) if ca_cert_path else None,
            connection_timeout=settings.CONNECTION_TIMEOUT,
            retry_attempts=settings.RETRY_ATTEMPTS
        )
        
        # create connection instance
        connection_instance = VPNConnection(config)
        vpn_connection = connection_instance  # set global for web ui
        
        # setup status callback for web ui
        def on_status_change(status: ConnectionStatus):
            global connection_status
            connection_status = status
        
        connection_instance.on_status_change = on_status_change
        
        # immediate connect mode
        if args.connect:
            logger.info("connecting immediately as requested")
            if connection_instance.connect():
                print(f"\nConnected successfully!")
                print(f"Virtual IP: {connection_instance.virtual_ip}")
                print("Press Ctrl+C to disconnect and exit")
                
                try:
                    while connection_instance.status == ConnectionStatus.CONNECTED:
                        if sys.platform == "win32":
                            time.sleep(1)
                        elif hasattr(signal, 'pause'):
                            signal.pause()
                        else:
                            time.sleep(1)
                except (KeyboardInterrupt, EOFError):
                    pass
            else:
                print("Connection failed")
                sys.exit(1)
        
        # cli mode
        elif args.no_ui:
            run_cli_mode(connection_instance)
        
        # web ui mode
        else:
            # start web ui in background thread
            web_thread = threading.Thread(
                target=run_web_ui,
                kwargs={
                    'host': args.ui_host,
                    'port': args.ui_port,
                    'debug': args.log_level == "DEBUG"
                },
                daemon=True
            )
            web_thread.start()
            
            # wait a moment for server to start
            import time
            time.sleep(1)
            
            # auto-launch browser
            if not args.no_browser and settings.WEB_UI_AUTO_LAUNCH:
                url = f"http://{args.ui_host}:{args.ui_port}"
                logger.info(f"opening browser: {url}")
                webbrowser.open(url)
            
            print("\n" + "=" * 50)
            print("kimoVPN Client Running")
            print("=" * 50)
            print(f"Web UI: http://{args.ui_host}:{args.ui_port}")
            print(f"Server: {server_host}:{server_port}")
            print(f"Username: {username}")
            print("\nPress Ctrl+C to stop the client")
            print("=" * 50 + "\n")
            
            # keep running
            try:
                while True:
                    if sys.platform == "win32":
                        time.sleep(1)
                    elif hasattr(signal, 'pause'):
                        signal.pause()
                    else:
                        time.sleep(1)
            except (KeyboardInterrupt, EOFError):
                pass
        
    except Exception as e:
        logger.error(f"client error: {e}", exc_info=True)
        if connection_instance:
            connection_instance.disconnect()
        sys.exit(1)
    
    finally:
        if connection_instance:
            connection_instance.disconnect()
        logger.info("client shutdown complete")


if __name__ == "__main__":
    main()
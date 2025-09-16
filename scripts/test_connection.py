#!/usr/bin/env python
"""
Connection Test Script

Simple script to test VPN client-server connection.
"""

import sys
import os
import time

# add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.client.connection import VPNConnection, ConnectionConfig
from src.common.logging import configure_logging
from src.common.models import ConnectionStatus


def test_connection():
    """Test VPN connection."""
    # configure logging
    configure_logging(log_level="INFO", service_name="test-client")
    
    print("\n" + "=" * 50)
    print("kimoVPN Connection Test")
    print("=" * 50)
    
    # create test configuration
    config = ConnectionConfig(
        server_host="127.0.0.1",
        server_port=13337,
        username="testuser",
        password="testpass123",
        ssl_verify=False,  # disable for self-signed cert
        ca_cert_path="certs/ca.crt",
        connection_timeout=10,
        retry_attempts=1
    )
    
    print(f"Server: {config.server_host}:{config.server_port}")
    print(f"Username: {config.username}")
    print("-" * 50)
    
    # create connection
    connection = VPNConnection(config)
    
    try:
        # test connection
        print("\n1. Testing connection...")
        start_time = time.time()
        
        if connection.connect():
            connect_time = time.time() - start_time
            print(f"   SUCCESS - Connected in {connect_time:.2f} seconds")
            print(f"   Virtual IP: {connection.virtual_ip}")
            print(f"   Session Token: {connection.session_token[:16]}...")
            
            # wait a bit
            print("\n2. Testing heartbeat...")
            time.sleep(5)
            
            if connection.status == ConnectionStatus.CONNECTED:
                print("   SUCCESS - Connection stable")
            else:
                print(f"   FAILED - Status: {connection.status.value}")
            
            # test disconnect
            print("\n3. Testing disconnect...")
            connection.disconnect()
            
            if connection.status == ConnectionStatus.DISCONNECTED:
                print("   SUCCESS - Disconnected cleanly")
            else:
                print(f"   FAILED - Status: {connection.status.value}")
            
            print("\n" + "=" * 50)
            print("All tests passed!")
            print("=" * 50)
            return True
            
        else:
            print(f"   FAILED - Could not connect")
            print(f"   Status: {connection.status.value}")
            return False
            
    except Exception as e:
        print(f"\nERROR: {e}")
        return False
        
    finally:
        if connection.status != ConnectionStatus.DISCONNECTED:
            connection.disconnect()


if __name__ == "__main__":
    # ensure server is running
    print("\nIMPORTANT: Make sure the VPN server is running:")
    print("  python -m src.server.main")
    print("\nPress Enter to continue or Ctrl+C to cancel...")
    
    try:
        input()
    except KeyboardInterrupt:
        print("\nCancelled")
        sys.exit(0)
    
    # run test
    success = test_connection()
    sys.exit(0 if success else 1)
#!/usr/bin/env python3
"""
Simple echo test to diagnose Phase 2 issues.
"""

import sys
import os
import time
import base64
from pathlib import Path

# add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.client.connection import VPNConnection, ConnectionConfig
from src.common.packet import PacketEncryptor, PacketEncoder, PacketType

def main():
    """Test basic echo functionality."""
    
    # connection config
    config = ConnectionConfig(
        server_host="localhost",
        server_port=13337,
        username="testuser",
        password="testpass123",
        ssl_verify=False,
        ca_cert_path=str(Path(__file__).parent.parent / "certs" / "ca.crt")
    )
    
    print("Phase 2 Echo Test Diagnostic")
    print("=" * 40)
    
    # test 1: basic connection
    print("\n1. Testing Connection...")
    vpn = VPNConnection(config)
    
    if not vpn.connect():
        print("   FAILED: Cannot connect")
        return 1
    
    print(f"   SUCCESS: Connected as {vpn.virtual_ip}")
    
    try:
        # test 2: packet encryption
        print("\n2. Testing Packet Encryption...")
        encryptor = PacketEncryptor()
        test_data = b"Hello VPN"
        
        encrypted = encryptor.encrypt(test_data)
        print(f"   Original: {test_data}")
        print(f"   Encrypted length: {len(encrypted)} bytes")
        
        decrypted = encryptor.decrypt(encrypted)
        print(f"   Decrypted: {decrypted}")
        
        if decrypted != test_data:
            print("   FAILED: Decryption mismatch")
            return 1
        print("   SUCCESS: Encryption works")
        
        # test 3: packet encoding
        print("\n3. Testing Packet Encoding...")
        encoder = PacketEncoder(encryptor)
        
        packet = encoder.encode(test_data, PacketType.ECHO_REQUEST)
        print(f"   Packet size: {len(packet)} bytes")
        print(f"   Base64 encoded size: {len(base64.b64encode(packet))} bytes")
        print("   SUCCESS: Packet encoded")
        
        # test 4: send echo through connection
        print("\n4. Testing Echo Through Connection...")
        
        # send a simple echo request
        vpn.packet_handler.send_echo_request(b"test")
        print("   Sent echo request")
        
        # wait for response
        time.sleep(1)
        
        # check if we got response
        if vpn.packet_handler.echo_latencies:
            latency = vpn.packet_handler.echo_latencies[0]
            print(f"   SUCCESS: Echo reply received, latency={latency*1000:.2f}ms")
        else:
            print("   WARNING: No echo reply received")
            
            # check stats
            stats = vpn.packet_handler.get_stats()
            print(f"   Stats: sent={stats['packets_sent']}, received={stats['packets_received']}")
            print(f"   Errors: encryption={stats.get('encryption_errors', 0)}, decryption={stats.get('decryption_errors', 0)}")
        
        print("\n" + "=" * 40)
        print("Diagnostic complete")
        
    finally:
        vpn.disconnect()
        print("\nDisconnected")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
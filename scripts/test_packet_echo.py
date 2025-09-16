#!/usr/bin/env python3
"""
Packet Echo Test Script

Tests the Phase 2 packet forwarding functionality with echo server.
Demonstrates encryption, packet handling, and performance metrics.
"""

import sys
import os
import time
import argparse
import json
from pathlib import Path

# add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.client.connection import VPNConnection, ConnectionConfig
from src.common.metrics import MetricsCollector, MetricsReporter
from src.common.logging import configure_logging


def test_echo(config: ConnectionConfig, test_params: dict) -> dict:
    """
    Run echo test with VPN server.
    
    Args:
        config: Connection configuration
        test_params: Test parameters
        
    Returns:
        Test results
    """
    # create connection
    vpn = VPNConnection(config)
    metrics = MetricsCollector()
    
    print(f"\nConnecting to {config.server_host}:{config.server_port}...")
    
    # connect and authenticate
    if not vpn.connect():
        print("FAILED: Failed to connect to VPN server")
        return {"error": "Connection failed"}
    
    print(f"SUCCESS: Connected successfully")
    print(f"   Username: {config.username}")
    print(f"   Virtual IP: {vpn.virtual_ip}")
    print(f"   Session Token: {vpn.session_token[:16]}...")
    
    # update metrics
    metrics.update_connection_status("connected")
    
    try:
        # wait a moment for connection to stabilize
        time.sleep(1)
        
        print("\n" + "="*50)
        print("Starting Packet Echo Test")
        print("="*50)
        
        # run echo test
        echo_results = vpn.run_echo_test(
            count=test_params.get("count", 10),
            payload_size=test_params.get("payload_size", 64),
            interval=test_params.get("interval", 0.5)
        )
        
        # update metrics with results
        if "latencies" in echo_results:
            for latency in echo_results["latencies"]:
                metrics.record_latency(latency)
        
        # print results
        print("\nEcho Test Results:")
        print("-" * 30)
        print(f"Packets Sent: {echo_results.get('sent', 0)}")
        print(f"Packets Received: {echo_results.get('received', 0)}")
        print(f"Packets Lost: {echo_results.get('lost', 0)}")
        print(f"Packet Loss: {echo_results.get('packet_loss_percent', 0):.1f}%")
        
        if echo_results.get('received', 0) > 0:
            print(f"\nLatency Statistics:")
            print(f"  Min: {echo_results.get('min_latency_ms', 0):.2f} ms")
            print(f"  Max: {echo_results.get('max_latency_ms', 0):.2f} ms")
            print(f"  Avg: {echo_results.get('avg_latency_ms', 0):.2f} ms")
        
        # get packet handler stats
        packet_stats = vpn.packet_handler.get_stats()
        print(f"\nPacket Handler Statistics:")
        print(f"  Packets Encrypted: {packet_stats.get('packets_encrypted', 0)}")
        print(f"  Packets Decrypted: {packet_stats.get('packets_decrypted', 0)}")
        print(f"  Bytes Sent: {packet_stats.get('bytes_sent', 0)}")
        print(f"  Bytes Received: {packet_stats.get('bytes_received', 0)}")
        
        # run throughput test if requested
        if test_params.get("throughput_test", False):
            print("\n" + "="*50)
            print("Starting Throughput Test")
            print("="*50)
            
            throughput_results = vpn.packet_tester.run_throughput_test(
                duration=test_params.get("throughput_duration", 5.0),
                packet_size=test_params.get("throughput_packet_size", 1400)
            )
            
            print("\nThroughput Test Results:")
            print("-" * 30)
            print(f"Duration: {throughput_results['duration_s']:.2f} seconds")
            print(f"Packets Sent: {throughput_results['packets_sent']}")
            print(f"Bytes Sent: {throughput_results['bytes_sent']}")
            print(f"Packets/Second: {throughput_results['packets_per_second']:.0f}")
            print(f"Throughput: {throughput_results['throughput_mbps']:.2f} Mbps")
        
        # collect final metrics
        final_metrics = metrics.get_current_metrics()
        
        print("\n" + "="*50)
        print("Overall Performance Summary")
        print("="*50)
        MetricsReporter.print_summary(final_metrics)
        
        return {
            "success": True,
            "echo": echo_results,
            "packet_stats": packet_stats,
            "metrics": final_metrics
        }
        
    except Exception as e:
        print(f"\nERROR: Test error: {e}")
        metrics.record_error(str(e))
        return {"error": str(e)}
        
    finally:
        print("\nDisconnecting...")
        vpn.disconnect()
        print("DONE: Disconnected")


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Test VPN packet echo functionality")
    
    # connection arguments
    parser.add_argument(
        "--server",
        default="localhost",
        help="VPN server address (default: localhost)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=13337,
        help="VPN server port (default: 13337)"
    )
    parser.add_argument(
        "--username",
        default="testuser",
        help="Username for authentication"
    )
    parser.add_argument(
        "--password",
        default="testpass123",
        help="Password for authentication"
    )
    
    # ssl arguments
    parser.add_argument(
        "--local",
        action="store_true",
        help="Use local testing configuration (no SSL verification)"
    )
    parser.add_argument(
        "--ca-cert",
        help="Path to CA certificate"
    )
    
    # echo test arguments
    parser.add_argument(
        "--count",
        type=int,
        default=10,
        help="Number of echo packets (default: 10)"
    )
    parser.add_argument(
        "--size",
        type=int,
        default=64,
        help="Echo payload size in bytes (default: 64)"
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=0.5,
        help="Interval between packets in seconds (default: 0.5)"
    )
    
    # throughput test arguments
    parser.add_argument(
        "--throughput",
        action="store_true",
        help="Run throughput test after echo test"
    )
    parser.add_argument(
        "--throughput-duration",
        type=float,
        default=5.0,
        help="Throughput test duration in seconds (default: 5.0)"
    )
    parser.add_argument(
        "--throughput-packet-size",
        type=int,
        default=1400,
        help="Throughput test packet size (default: 1400)"
    )
    
    # output arguments
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # setup logging
    if not args.json:
        configure_logging(log_level="DEBUG" if args.verbose else "INFO")
    
    # determine certificate path
    ca_cert_path = args.ca_cert
    if not ca_cert_path and args.local:
        # use local test certificate
        ca_cert_path = str(Path(__file__).parent.parent / "certs" / "ca.crt")
    
    # create connection config
    config = ConnectionConfig(
        server_host=args.server,
        server_port=args.port,
        username=args.username,
        password=args.password,
        ssl_verify=not args.local,
        ca_cert_path=ca_cert_path
    )
    
    # test parameters
    test_params = {
        "count": args.count,
        "payload_size": args.size,
        "interval": args.interval,
        "throughput_test": args.throughput,
        "throughput_duration": args.throughput_duration,
        "throughput_packet_size": args.throughput_packet_size
    }
    
    if not args.json:
        print("\n" + "="*50)
        print("VPN Packet Echo Test")
        print("="*50)
        print(f"Server: {config.server_host}:{config.server_port}")
        print(f"Echo Packets: {test_params['count']}")
        print(f"Payload Size: {test_params['payload_size']} bytes")
        print(f"Interval: {test_params['interval']} seconds")
        if args.throughput:
            print(f"Throughput Test: Enabled ({test_params['throughput_duration']}s)")
    
    # run test
    results = test_echo(config, test_params)
    
    # output results
    if args.json:
        print(json.dumps(results, indent=2))
    
    # exit code based on success
    sys.exit(0 if results.get("success") else 1)


if __name__ == "__main__":
    main()
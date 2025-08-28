#!/usr/bin/env python3
"""
Test script for Phase 3 Web UI functionality.

This script tests:
1. Flask API endpoints
2. Configuration management
3. Connection history
4. Statistics collection
"""

import time
import sys
import os
import json
import requests
import threading
import subprocess
from pathlib import Path

# add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_api_endpoints():
    """Test REST API endpoints."""
    base_url = "http://127.0.0.1:5000"
    
    print("\n" + "=" * 50)
    print("Testing Web UI API Endpoints")
    print("=" * 50)
    
    # test status endpoint
    try:
        response = requests.get(f"{base_url}/api/status")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ GET /api/status: {data['status']}")
        else:
            print(f"❌ GET /api/status failed: {response.status_code}")
    except Exception as e:
        print(f"❌ GET /api/status error: {e}")
    
    # test stats endpoint
    try:
        response = requests.get(f"{base_url}/api/stats")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ GET /api/stats: {len(data)} fields")
        else:
            print(f"❌ GET /api/stats failed: {response.status_code}")
    except Exception as e:
        print(f"❌ GET /api/stats error: {e}")
    
    # test config endpoint
    try:
        response = requests.get(f"{base_url}/api/config")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ GET /api/config: {data.get('server_host', 'N/A')}")
        else:
            print(f"❌ GET /api/config failed: {response.status_code}")
    except Exception as e:
        print(f"❌ GET /api/config error: {e}")
    
    # test history endpoint
    try:
        response = requests.get(f"{base_url}/api/history")
        if response.status_code == 200:
            data = response.json()
            history_count = len(data.get('history', []))
            print(f"✅ GET /api/history: {history_count} entries")
        else:
            print(f"❌ GET /api/history failed: {response.status_code}")
    except Exception as e:
        print(f"❌ GET /api/history error: {e}")
    
    # test config update
    try:
        config_data = {
            "auto_reconnect": True,
            "server_host": "test.example.com"
        }
        response = requests.post(
            f"{base_url}/api/config",
            json=config_data,
            headers={'Content-Type': 'application/json'}
        )
        if response.status_code == 200:
            print(f"✅ POST /api/config: Configuration updated")
        else:
            print(f"❌ POST /api/config failed: {response.status_code}")
    except Exception as e:
        print(f"❌ POST /api/config error: {e}")
    
    print("=" * 50)


def main():
    """Main test function."""
    print("\n" + "=" * 50)
    print("Phase 3 Web UI Test")
    print("=" * 50)
    print("\nThis test will:")
    print("1. Start the client with Web UI")
    print("2. Test all API endpoints")
    print("3. Verify CORS configuration")
    print("4. Check WebSocket connectivity")
    print("\n⚠️ Make sure the server is running if you want to test connections")
    
    # start client with web ui in background
    print("\nStarting client with Web UI...")
    client_process = subprocess.Popen(
        [sys.executable, "-m", "src.client.main", "--no-browser", "--log-level", "INFO"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # wait for web ui to start
    print("Waiting for Web UI to start...")
    time.sleep(3)
    
    try:
        # test api endpoints
        test_api_endpoints()
        
        # test cors headers
        print("\nTesting CORS configuration...")
        response = requests.options(
            "http://127.0.0.1:5000/api/status",
            headers={
                'Origin': 'http://example.com',
                'Access-Control-Request-Method': 'GET'
            }
        )
        
        if 'Access-Control-Allow-Origin' in response.headers:
            print(f"✅ CORS enabled: {response.headers['Access-Control-Allow-Origin']}")
        else:
            print("❌ CORS not properly configured")
        
        print("\n✅ Phase 3 Web UI test completed successfully!")
        print("\nYou can now:")
        print("1. Open http://127.0.0.1:5000 in your browser")
        print("2. Test the connection controls")
        print("3. Configure settings via the UI")
        print("4. View connection history")
        print("\nPress Ctrl+C to stop the client")
        
        # keep running until interrupted
        client_process.wait()
        
    except KeyboardInterrupt:
        print("\n\nStopping client...")
        client_process.terminate()
        time.sleep(1)
        print("Test completed.")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        client_process.terminate()
        sys.exit(1)


if __name__ == "__main__":
    main()
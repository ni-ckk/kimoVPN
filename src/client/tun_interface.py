"""
Windows TUN interface implementation for VPN client.
"""

import os
import sys
import platform
import threading
import queue
import subprocess
from typing import Optional, Callable, Dict, Any
from ipaddress import IPv4Address, IPv4Network

from structlog import get_logger

logger = get_logger()

# platform detection
IS_WINDOWS = platform.system() == 'Windows'
IS_LINUX = platform.system() == 'Linux'
PLATFORM = platform.system()

# windows-specific imports
if IS_WINDOWS:
    try:
        import win32api
        import win32file
        import win32event
        import pywintypes
        WIN32_AVAILABLE = True
    except ImportError:
        logger.warning("pywin32 not available - limited functionality")
        WIN32_AVAILABLE = False
else:
    WIN32_AVAILABLE = False


class WindowsTunInterface:
    """
    Windows TUN interface implementation.
    
    Note: This is a simplified implementation. For production use,
    consider using WireGuard's Wintun driver or OpenVPN's TAP driver.
    """
    
    def __init__(
        self,
        name: str = "kimoVPN",
        ip_address: str = "10.8.0.2",
        netmask: str = "255.255.255.0",
        gateway: str = "10.8.0.1",
        mtu: int = 1500
    ):
        """
        Initialize Windows TUN interface.
        
        Args:
            name: Interface name
            ip_address: Client IP address
            netmask: Network mask
            gateway: Gateway IP address
            mtu: Maximum transmission unit
        """
        self.name = name
        self.ip_address = ip_address
        self.netmask = netmask
        self.gateway = gateway
        self.network = IPv4Network(f"{ip_address}/{netmask}", strict=False)
        self.mtu = mtu
        
        self.handle = None
        self.running = False
        self.read_thread = None
        self.write_queue = queue.Queue()
        
        # callbacks
        self.on_packet_received: Optional[Callable[[bytes], None]] = None
        
        # routing backup
        self.original_routes = []
        
        logger.info(
            "initializing windows tun interface",
            name=name,
            ip=ip_address,
            gateway=gateway
        )
    
    def create(self) -> bool:
        """
        Create and configure TUN interface.
        
        Returns:
            True if successful
        """
        try:
            # for windows, we'll use a simplified approach
            # in production, you'd use wintun or tap-windows driver
            
            # create virtual adapter using netsh (requires admin)
            if not self._create_virtual_adapter():
                return False
            
            # configure ip address
            if not self._configure_ip():
                return False
            
            logger.info(f"tun interface {self.name} created successfully")
            return True
            
        except Exception as e:
            logger.error(f"failed to create tun interface: {e}")
            return False
    
    def _create_virtual_adapter(self) -> bool:
        """Create virtual network adapter."""
        # note: this is a simplified approach
        # for production, use wintun driver or tap-windows
        
        logger.info("creating virtual adapter (mock implementation)")
        
        # check if running as admin
        if WIN32_AVAILABLE:
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                if not is_admin:
                    logger.warning("not running as administrator - limited functionality")
            except:
                pass
        
        return True
    
    def _configure_ip(self) -> bool:
        """Configure IP address on interface."""
        try:
            # use netsh to configure ip (requires admin)
            commands = [
                f'netsh interface ip set address "{self.name}" static {self.ip_address} {self.netmask} {self.gateway}',
                f'netsh interface ip set dns "{self.name}" static 8.8.8.8',
                f'netsh interface ip add dns "{self.name}" 8.8.4.4 index=2'
            ]
            
            for cmd in commands:
                logger.debug(f"executing: {cmd}")
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.returncode != 0 and "Cannot find" not in result.stderr:
                    logger.warning(f"command failed: {result.stderr}")
            
            return True
            
        except Exception as e:
            logger.error(f"failed to configure ip: {e}")
            return False
    
    def start(self) -> bool:
        """
        Start interface operation.
        
        Returns:
            True if started successfully
        """
        if self.running:
            logger.warning("interface already running")
            return True
        
        self.running = True
        
        # start read thread (mock for now)
        self.read_thread = threading.Thread(
            target=self._read_loop,
            daemon=True
        )
        self.read_thread.start()
        
        # start write thread
        self.write_thread = threading.Thread(
            target=self._write_loop,
            daemon=True
        )
        self.write_thread.start()
        
        # configure routing
        self._setup_routing()
        
        logger.info(f"tun interface {self.name} started")
        return True
    
    def stop(self):
        """Stop interface operation."""
        self.running = False
        
        # restore routing
        self._restore_routing()
        
        # wait for threads
        if self.read_thread:
            self.read_thread.join(timeout=1)
        if hasattr(self, 'write_thread') and self.write_thread:
            self.write_thread.join(timeout=1)
        
        logger.info(f"tun interface {self.name} stopped")
    
    def destroy(self):
        """Destroy TUN interface."""
        self.stop()
        
        # remove virtual adapter
        self._remove_virtual_adapter()
        
        logger.info(f"tun interface {self.name} destroyed")
    
    def _remove_virtual_adapter(self):
        """Remove virtual network adapter."""
        logger.info("removing virtual adapter (mock implementation)")
        # in production, properly remove the adapter
        pass
    
    def write_packet(self, data: bytes):
        """
        Write packet to TUN interface.
        
        Args:
            data: Packet data
        """
        if not self.running:
            logger.warning("cannot write - interface not running")
            return
        
        self.write_queue.put(data)
    
    def _read_loop(self):
        """Read packets from TUN interface (mock implementation)."""
        logger.debug(f"starting read loop for {self.name}")
        
        # mock implementation - in production, read from actual driver
        while self.running:
            try:
                # simulate reading
                import time
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"read error: {e}")
                break
        
        logger.debug(f"read loop stopped for {self.name}")
    
    def _write_loop(self):
        """Write packets to TUN interface."""
        logger.debug(f"starting write loop for {self.name}")
        
        while self.running:
            try:
                # get packet from queue
                data = self.write_queue.get(timeout=0.1)
                
                # in production, write to actual driver
                # for now, just log
                logger.debug(f"would write {len(data)} bytes to interface")
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"write error: {e}")
                break
        
        logger.debug(f"write loop stopped for {self.name}")
    
    def _setup_routing(self):
        """Setup routing table for VPN."""
        try:
            # backup current default route
            result = subprocess.run(
                "route print 0.0.0.0",
                shell=True,
                capture_output=True,
                text=True
            )
            self.original_routes.append(result.stdout)
            
            # add routes for vpn
            commands = [
                # add route to vpn server through original gateway
                f"route add {self.gateway} mask 255.255.255.255 0.0.0.0",
                # add default route through vpn
                f"route add 0.0.0.0 mask 0.0.0.0 {self.gateway} metric 1"
            ]
            
            for cmd in commands:
                logger.debug(f"adding route: {cmd}")
                subprocess.run(cmd, shell=True, capture_output=True)
            
            logger.info("routing table configured for vpn")
            
        except Exception as e:
            logger.error(f"failed to setup routing: {e}")
    
    def _restore_routing(self):
        """Restore original routing table."""
        try:
            # remove vpn routes
            commands = [
                f"route delete 0.0.0.0 mask 0.0.0.0 {self.gateway}",
                f"route delete {self.gateway}"
            ]
            
            for cmd in commands:
                subprocess.run(cmd, shell=True, capture_output=True)
            
            logger.info("routing table restored")
            
        except Exception as e:
            logger.error(f"failed to restore routing: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get interface statistics.
        
        Returns:
            Statistics dictionary
        """
        return {
            "name": self.name,
            "ip_address": self.ip_address,
            "gateway": self.gateway,
            "network": str(self.network),
            "mtu": self.mtu,
            "running": self.running,
            "platform": "windows"
        }


class WintunInterface:
    """
    Wintun-based TUN interface for Windows.
    
    This is a placeholder for future Wintun integration.
    Wintun is the modern, lightweight TUN driver from WireGuard.
    """
    
    def __init__(self, **kwargs):
        """Initialize Wintun interface."""
        logger.info("wintun interface placeholder - not yet implemented")
        logger.info("for production, integrate wintun.dll")
        
        # fall back to mock implementation
        self.mock = MockWindowsTunInterface(**kwargs)
    
    def create(self) -> bool:
        """Create interface."""
        return self.mock.create()
    
    def start(self) -> bool:
        """Start interface."""
        return self.mock.start()
    
    def stop(self):
        """Stop interface."""
        self.mock.stop()
    
    def destroy(self):
        """Destroy interface."""
        self.mock.destroy()
    
    def write_packet(self, data: bytes):
        """Write packet."""
        self.mock.write_packet(data)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get stats."""
        return self.mock.get_stats()


class MockWindowsTunInterface:
    """Mock TUN interface for testing."""
    
    def __init__(
        self,
        name: str = "kimoVPN",
        ip_address: str = "10.8.0.2",
        netmask: str = "255.255.255.0",
        gateway: str = "10.8.0.1",
        mtu: int = 1500
    ):
        """Initialize mock interface."""
        self.name = name
        self.ip_address = ip_address
        self.netmask = netmask
        self.gateway = gateway
        self.network = IPv4Network(f"{ip_address}/{netmask}", strict=False)
        self.mtu = mtu
        self.running = False
        self.on_packet_received: Optional[Callable[[bytes], None]] = None
        
        logger.info(f"initialized mock windows tun interface {name}")
    
    def create(self) -> bool:
        """Mock create."""
        logger.info(f"mock: created interface {self.name}")
        return True
    
    def start(self) -> bool:
        """Mock start."""
        self.running = True
        logger.info(f"mock: started interface {self.name}")
        return True
    
    def stop(self):
        """Mock stop."""
        self.running = False
        logger.info(f"mock: stopped interface {self.name}")
    
    def destroy(self):
        """Mock destroy."""
        self.stop()
        logger.info(f"mock: destroyed interface {self.name}")
    
    def write_packet(self, data: bytes):
        """Mock write packet."""
        logger.debug(f"mock: write packet of {len(data)} bytes")
        # echo back for testing
        if self.on_packet_received:
            self.on_packet_received(data)
    
    def get_stats(self) -> Dict[str, Any]:
        """Mock stats."""
        return {
            "name": self.name,
            "ip_address": self.ip_address,
            "gateway": self.gateway,
            "network": str(self.network),
            "mtu": self.mtu,
            "running": self.running,
            "mock": True
        }


# factory function
def create_tun_interface(**kwargs) -> WindowsTunInterface:
    """
    Create appropriate TUN interface for Windows.
    
    Returns:
        TUN interface instance
    """
    # check if wintun is available
    wintun_available = False  # todo: check for wintun.dll
    
    if wintun_available:
        return WintunInterface(**kwargs)
    elif WIN32_AVAILABLE:
        return WindowsTunInterface(**kwargs)
    else:
        logger.warning("no windows tun driver available - using mock")
        return MockWindowsTunInterface(**kwargs)
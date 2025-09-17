"""
Linux TUN interface implementation for VPN server.
"""

import os
import sys
import platform
import struct
import threading
import queue
from typing import Optional, Callable, Dict, Any
from ipaddress import IPv4Address, IPv4Network

from structlog import get_logger

logger = get_logger()

# platform detection
IS_LINUX = platform.system() == 'Linux'
IS_WINDOWS = platform.system() == 'Windows'
PLATFORM = platform.system()

# linux-specific imports (will fail on windows)
if IS_LINUX:
    try:
        import fcntl
        from pyroute2 import IPRoute, NDB
        PYROUTE2_AVAILABLE = True
    except ImportError:
        logger.warning("pyroute2 not available - limited functionality")
        PYROUTE2_AVAILABLE = False
else:
    PYROUTE2_AVAILABLE = False
    fcntl = None  # placeholder for non-linux systems


# tun/tap ioctl constants for linux
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454ca


class LinuxTunInterface:
    """Linux TUN interface implementation."""
    
    def __init__(
        self,
        name: str = "tun0",
        ip_address: str = "10.8.0.1",
        netmask: str = "255.255.255.0",
        mtu: int = 1500
    ):
        """
        Initialize Linux TUN interface.
        
        Args:
            name: Interface name
            ip_address: IP address for interface
            netmask: Network mask
            mtu: Maximum transmission unit
        """
        self.name = name
        self.ip_address = ip_address
        self.netmask = netmask
        self.network = IPv4Network(f"{ip_address}/{netmask}", strict=False)
        self.mtu = mtu
        
        self.fd = None
        self.running = False
        self.read_thread = None
        self.write_queue = queue.Queue()
        
        # callbacks
        self.on_packet_received: Optional[Callable[[bytes], None]] = None
        
        logger.info(
            "initializing linux tun interface",
            name=name,
            ip=ip_address,
            network=str(self.network)
        )
    
    def create(self) -> bool:
        """
        Create and configure TUN interface.
        
        Returns:
            True if successful
        """
        try:
            # open tun device
            self.fd = os.open("/dev/net/tun", os.O_RDWR)
            
            # configure interface
            ifr = struct.pack("16sH", self.name.encode(), IFF_TUN | IFF_NO_PI)
            fcntl.ioctl(self.fd, TUNSETIFF, ifr)
            
            # configure ip address and bring up interface
            if PYROUTE2_AVAILABLE:
                self._configure_with_pyroute2()
            else:
                self._configure_with_commands()
            
            logger.info(f"tun interface {self.name} created successfully")
            return True
            
        except Exception as e:
            logger.error(f"failed to create tun interface: {e}")
            if self.fd:
                os.close(self.fd)
                self.fd = None
            return False
    
    def _configure_with_pyroute2(self):
        """Configure interface using pyroute2."""
        with IPRoute() as ipr:
            # get interface index
            links = ipr.link("dump", ifname=self.name)
            if not links:
                raise ValueError(f"Interface {self.name} not found")
            
            idx = links[0]["index"]
            
            # set mtu
            ipr.link("set", index=idx, mtu=self.mtu)
            
            # add ip address
            ipr.addr("add", index=idx, address=self.ip_address, 
                    prefixlen=self.network.prefixlen)
            
            # bring interface up
            ipr.link("set", index=idx, state="up")
    
    def _configure_with_commands(self):
        """Configure interface using system commands."""
        import subprocess
        
        commands = [
            f"ip addr add {self.ip_address}/{self.network.prefixlen} dev {self.name}",
            f"ip link set dev {self.name} mtu {self.mtu}",
            f"ip link set dev {self.name} up"
        ]
        
        for cmd in commands:
            result = subprocess.run(cmd.split(), capture_output=True)
            if result.returncode != 0:
                logger.warning(f"command failed: {cmd}, error: {result.stderr}")
    
    def start(self) -> bool:
        """
        Start interface operation.
        
        Returns:
            True if started successfully
        """
        if not self.fd:
            logger.error("cannot start - interface not created")
            return False
        
        if self.running:
            logger.warning("interface already running")
            return True
        
        self.running = True
        
        # start read thread
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
        
        logger.info(f"tun interface {self.name} started")
        return True
    
    def stop(self):
        """Stop interface operation."""
        self.running = False
        
        # wait for threads to stop
        if self.read_thread:
            self.read_thread.join(timeout=1)
        if hasattr(self, 'write_thread') and self.write_thread:
            self.write_thread.join(timeout=1)
        
        logger.info(f"tun interface {self.name} stopped")
    
    def destroy(self):
        """Destroy TUN interface."""
        self.stop()
        
        if self.fd:
            os.close(self.fd)
            self.fd = None
        
        # remove interface configuration
        if PYROUTE2_AVAILABLE:
            try:
                with IPRoute() as ipr:
                    links = ipr.link("dump", ifname=self.name)
                    if links:
                        ipr.link("delete", index=links[0]["index"])
            except Exception as e:
                logger.error(f"failed to delete interface: {e}")
        
        logger.info(f"tun interface {self.name} destroyed")
    
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
        """Read packets from TUN interface."""
        logger.debug(f"starting read loop for {self.name}")
        
        while self.running:
            try:
                # read packet from tun
                data = os.read(self.fd, self.mtu + 100)  # extra space for headers
                
                if not data:
                    continue
                
                # notify callback
                if self.on_packet_received:
                    self.on_packet_received(data)
                
            except OSError as e:
                if self.running:
                    logger.error(f"read error: {e}")
                    break
            except Exception as e:
                logger.error(f"unexpected read error: {e}")
                break
        
        logger.debug(f"read loop stopped for {self.name}")
    
    def _write_loop(self):
        """Write packets to TUN interface."""
        logger.debug(f"starting write loop for {self.name}")
        
        while self.running:
            try:
                # get packet from queue (with timeout)
                data = self.write_queue.get(timeout=0.1)
                
                # write to tun
                os.write(self.fd, data)
                
            except queue.Empty:
                continue
            except OSError as e:
                if self.running:
                    logger.error(f"write error: {e}")
                    break
            except Exception as e:
                logger.error(f"unexpected write error: {e}")
                break
        
        logger.debug(f"write loop stopped for {self.name}")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get interface statistics.
        
        Returns:
            Statistics dictionary
        """
        stats = {
            "name": self.name,
            "ip_address": self.ip_address,
            "network": str(self.network),
            "mtu": self.mtu,
            "running": self.running
        }
        
        # get interface stats if available
        if PYROUTE2_AVAILABLE and self.running:
            try:
                with IPRoute() as ipr:
                    links = ipr.link("dump", ifname=self.name)
                    if links:
                        link = links[0]
                        stats.update({
                            "tx_packets": link.get("stats64", {}).get("tx_packets", 0),
                            "rx_packets": link.get("stats64", {}).get("rx_packets", 0),
                            "tx_bytes": link.get("stats64", {}).get("tx_bytes", 0),
                            "rx_bytes": link.get("stats64", {}).get("rx_bytes", 0),
                        })
            except Exception as e:
                logger.debug(f"failed to get interface stats: {e}")
        
        return stats


class MockTunInterface:
    """Mock TUN interface for testing on non-Linux systems."""
    
    def __init__(
        self,
        name: str = "tun0",
        ip_address: str = "10.8.0.1",
        netmask: str = "255.255.255.0",
        mtu: int = 1500
    ):
        """Initialize mock interface."""
        self.name = name
        self.ip_address = ip_address
        self.netmask = netmask
        self.network = IPv4Network(f"{ip_address}/{netmask}", strict=False)
        self.mtu = mtu
        self.running = False
        self.on_packet_received: Optional[Callable[[bytes], None]] = None
        
        logger.info(f"initialized mock tun interface {name}")
    
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
            "network": str(self.network),
            "mtu": self.mtu,
            "running": self.running,
            "mock": True
        }


# factory function
def create_tun_interface(**kwargs) -> LinuxTunInterface:
    """
    Create appropriate TUN interface for platform.
    
    Returns:
        TUN interface instance
    """
    if sys.platform.startswith('linux'):
        return LinuxTunInterface(**kwargs)
    else:
        logger.warning("not on linux - using mock interface")
        return MockTunInterface(**kwargs)
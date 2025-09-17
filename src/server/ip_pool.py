"""
IP address pool management for VPN clients.
"""

import json
import threading
from pathlib import Path
from typing import Optional, Dict, Set, List
from ipaddress import IPv4Network, IPv4Address
from datetime import datetime

from pydantic import BaseModel, Field
from structlog import get_logger

logger = get_logger()


class IPAssignment(BaseModel):
    """Represents an IP address assignment."""
    ip_address: str
    username: str
    assigned_at: datetime
    last_seen: datetime
    active: bool = True


class IPPool:
    """Manages IP address assignments for VPN clients."""
    
    def __init__(
        self,
        network: str = "10.8.0.0/24",
        server_ip: str = "10.8.0.1",
        persistence_file: Optional[Path] = None
    ):
        """
        Initialize IP pool.
        
        Args:
            network: Network in CIDR notation
            server_ip: Server's IP address (excluded from pool)
            persistence_file: File to persist assignments
        """
        self.network = IPv4Network(network)
        self.server_ip = IPv4Address(server_ip)
        self.persistence_file = persistence_file
        
        # thread safety
        self.lock = threading.Lock()
        
        # initialize available ips (exclude network, broadcast, and server)
        self.available_ips: Set[str] = set()
        self._initialize_pool()
        
        # track assignments: username -> ip
        self.assignments: Dict[str, str] = {}
        # reverse mapping: ip -> username
        self.ip_to_user: Dict[str, str] = {}
        
        # assignment history
        self.history: List[IPAssignment] = []
        
        # load persisted assignments
        if self.persistence_file and self.persistence_file.exists():
            self._load_assignments()
    
    def _initialize_pool(self):
        """Initialize available IP addresses."""
        for ip in self.network.hosts():
            # skip server ip
            if ip == self.server_ip:
                continue
            # skip .0 and .255 for /24 networks
            if ip == self.network.network_address or ip == self.network.broadcast_address:
                continue
            self.available_ips.add(str(ip))
        
        logger.info(
            "ip pool initialized",
            network=str(self.network),
            available=len(self.available_ips)
        )
    
    def assign_ip(self, username: str) -> Optional[str]:
        """
        Assign an IP address to a user.
        
        Args:
            username: Username to assign IP to
            
        Returns:
            Assigned IP address or None if pool exhausted
        """
        with self.lock:
            # check if user already has an assignment
            if username in self.assignments:
                ip = self.assignments[username]
                logger.debug(f"reusing existing ip {ip} for {username}")
                
                # update last seen
                for assignment in self.history:
                    if assignment.username == username and assignment.ip_address == ip:
                        assignment.last_seen = datetime.now()
                        assignment.active = True
                        break
                
                return ip
            
            # check if we have available ips
            if not self.available_ips:
                logger.error("ip pool exhausted")
                return None
            
            # assign next available ip
            ip = self.available_ips.pop()
            self.assignments[username] = ip
            self.ip_to_user[ip] = username
            
            # record assignment
            assignment = IPAssignment(
                ip_address=ip,
                username=username,
                assigned_at=datetime.now(),
                last_seen=datetime.now(),
                active=True
            )
            self.history.append(assignment)
            
            logger.info(f"assigned ip {ip} to {username}")
            
            # persist if configured
            if self.persistence_file:
                self._save_assignments()
            
            return ip
    
    def release_ip(self, username: str) -> bool:
        """
        Release an IP address assignment.
        
        Args:
            username: Username to release IP for
            
        Returns:
            True if released successfully
        """
        with self.lock:
            if username not in self.assignments:
                logger.warning(f"no ip assignment found for {username}")
                return False
            
            ip = self.assignments[username]
            
            # remove assignments
            del self.assignments[username]
            del self.ip_to_user[ip]
            
            # return ip to pool
            self.available_ips.add(ip)
            
            # mark as inactive in history
            for assignment in self.history:
                if assignment.username == username and assignment.ip_address == ip:
                    assignment.active = False
                    assignment.last_seen = datetime.now()
                    break
            
            logger.info(f"released ip {ip} from {username}")
            
            # persist if configured
            if self.persistence_file:
                self._save_assignments()
            
            return True
    
    def get_user_by_ip(self, ip: str) -> Optional[str]:
        """
        Get username by IP address.
        
        Args:
            ip: IP address
            
        Returns:
            Username or None if not assigned
        """
        with self.lock:
            return self.ip_to_user.get(ip)
    
    def get_ip_by_user(self, username: str) -> Optional[str]:
        """
        Get IP address by username.
        
        Args:
            username: Username
            
        Returns:
            IP address or None if not assigned
        """
        with self.lock:
            return self.assignments.get(username)
    
    def get_all_assignments(self) -> Dict[str, str]:
        """
        Get all current assignments.
        
        Returns:
            Dictionary of username -> ip mappings
        """
        with self.lock:
            return self.assignments.copy()
    
    def get_pool_status(self) -> Dict:
        """
        Get pool status information.
        
        Returns:
            Status dictionary
        """
        with self.lock:
            return {
                "network": str(self.network),
                "server_ip": str(self.server_ip),
                "total_ips": len(self.available_ips) + len(self.assignments),
                "available": len(self.available_ips),
                "assigned": len(self.assignments),
                "assignments": self.assignments.copy()
            }
    
    def cleanup_inactive(self, timeout_hours: int = 24):
        """
        Clean up inactive assignments.
        
        Args:
            timeout_hours: Hours of inactivity before cleanup
        """
        with self.lock:
            now = datetime.now()
            to_release = []
            
            for assignment in self.history:
                if not assignment.active:
                    continue
                
                # check if inactive for too long
                inactive_hours = (now - assignment.last_seen).total_seconds() / 3600
                if inactive_hours > timeout_hours:
                    to_release.append(assignment.username)
            
            # release inactive assignments
            for username in to_release:
                self.release_ip(username)
                logger.info(f"cleaned up inactive assignment for {username}")
    
    def _save_assignments(self):
        """Save assignments to file."""
        if not self.persistence_file:
            return
        
        try:
            data = {
                "network": str(self.network),
                "server_ip": str(self.server_ip),
                "assignments": self.assignments,
                "history": [
                    {
                        "ip_address": a.ip_address,
                        "username": a.username,
                        "assigned_at": a.assigned_at.isoformat(),
                        "last_seen": a.last_seen.isoformat(),
                        "active": a.active
                    }
                    for a in self.history
                ]
            }
            
            self.persistence_file.parent.mkdir(parents=True, exist_ok=True)
            self.persistence_file.write_text(json.dumps(data, indent=2))
            
        except Exception as e:
            logger.error(f"failed to save assignments: {e}")
    
    def _load_assignments(self):
        """Load assignments from file."""
        if not self.persistence_file or not self.persistence_file.exists():
            return
        
        try:
            data = json.loads(self.persistence_file.read_text())
            
            # restore active assignments
            for username, ip in data.get("assignments", {}).items():
                if ip in self.available_ips:
                    self.available_ips.remove(ip)
                    self.assignments[username] = ip
                    self.ip_to_user[ip] = username
            
            # restore history
            for item in data.get("history", []):
                assignment = IPAssignment(
                    ip_address=item["ip_address"],
                    username=item["username"],
                    assigned_at=datetime.fromisoformat(item["assigned_at"]),
                    last_seen=datetime.fromisoformat(item["last_seen"]),
                    active=item["active"]
                )
                self.history.append(assignment)
            
            logger.info(
                "loaded ip assignments",
                active=len(self.assignments),
                history=len(self.history)
            )
            
        except Exception as e:
            logger.error(f"failed to load assignments: {e}")


class IPPoolManager:
    """Manages multiple IP pools for different networks."""
    
    def __init__(self):
        """Initialize pool manager."""
        self.pools: Dict[str, IPPool] = {}
        self.lock = threading.Lock()
    
    def create_pool(
        self,
        name: str,
        network: str,
        server_ip: str,
        persistence_file: Optional[Path] = None
    ) -> IPPool:
        """
        Create a new IP pool.
        
        Args:
            name: Pool name
            network: Network in CIDR notation
            server_ip: Server IP address
            persistence_file: Persistence file path
            
        Returns:
            Created IP pool
        """
        with self.lock:
            if name in self.pools:
                raise ValueError(f"Pool {name} already exists")
            
            pool = IPPool(network, server_ip, persistence_file)
            self.pools[name] = pool
            return pool
    
    def get_pool(self, name: str) -> Optional[IPPool]:
        """
        Get pool by name.
        
        Args:
            name: Pool name
            
        Returns:
            IP pool or None
        """
        with self.lock:
            return self.pools.get(name)
    
    def remove_pool(self, name: str) -> bool:
        """
        Remove a pool.
        
        Args:
            name: Pool name
            
        Returns:
            True if removed successfully
        """
        with self.lock:
            if name in self.pools:
                del self.pools[name]
                return True
            return False
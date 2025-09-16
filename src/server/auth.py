"""
Authentication Module

Handles user authentication and management for the VPN server.
"""

import json
import time
from pathlib import Path
from typing import Dict, Optional, List
from dataclasses import dataclass, field
from passlib.context import CryptContext
import structlog

logger = structlog.get_logger()

# password hashing context using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@dataclass
class User:
    """User account information."""
    username: str
    password_hash: str
    enabled: bool = True
    max_sessions: int = 1
    created_at: float = field(default_factory=time.time)


@dataclass
class AuthAttempt:
    """Authentication attempt tracking."""
    ip_address: str
    timestamp: float
    success: bool
    username: Optional[str] = None


class AuthManager:
    """Manages user authentication and rate limiting."""
    
    def __init__(
        self,
        users_file: str = "data/users.json",
        max_attempts: int = 5,
        window_seconds: int = 300
    ):
        """
        Initialize authentication manager.
        
        Args:
            users_file: Path to users JSON file
            max_attempts: Max auth attempts per window
            window_seconds: Time window for rate limiting
        """
        self.users_file = Path(users_file)
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.users: Dict[str, User] = {}
        self.auth_attempts: List[AuthAttempt] = []
        self.active_sessions: Dict[str, str] = {}  # username -> session_token
        
        # ensure data directory exists
        self.users_file.parent.mkdir(parents=True, exist_ok=True)
        
        # load existing users or create default
        self.load_users()
    
    def load_users(self):
        """Load users from JSON file."""
        if self.users_file.exists():
            try:
                with open(self.users_file, 'r') as f:
                    users_data = json.load(f)
                    
                for username, user_info in users_data.items():
                    self.users[username] = User(
                        username=username,
                        password_hash=user_info["password_hash"],
                        enabled=user_info.get("enabled", True),
                        max_sessions=user_info.get("max_sessions", 1),
                        created_at=user_info.get("created_at", time.time())
                    )
                
                logger.info(f"loaded {len(self.users)} users from file")
                
            except Exception as e:
                logger.error(f"failed to load users file", error=str(e))
                self.create_default_users()
        else:
            self.create_default_users()
    
    def create_default_users(self):
        """Create default test users."""
        logger.info("creating default test users")
        
        # create test user
        self.add_user("testuser", "testpass123")
        self.add_user("admin", "admin123")
        
        self.save_users()
    
    def save_users(self):
        """Save users to JSON file."""
        users_data = {}
        for username, user in self.users.items():
            users_data[username] = {
                "password_hash": user.password_hash,
                "enabled": user.enabled,
                "max_sessions": user.max_sessions,
                "created_at": user.created_at
            }
        
        try:
            with open(self.users_file, 'w') as f:
                json.dump(users_data, f, indent=2)
            logger.info("saved users to file")
        except Exception as e:
            logger.error("failed to save users", error=str(e))
    
    def add_user(self, username: str, password: str) -> bool:
        """
        Add a new user.
        
        Args:
            username: Username to add
            password: Plain text password
            
        Returns:
            True if user added, False if already exists
        """
        if username in self.users:
            return False
        
        password_hash = pwd_context.hash(password)
        self.users[username] = User(
            username=username,
            password_hash=password_hash
        )
        
        logger.info("added new user", username=username)
        return True
    
    def verify_password(self, username: str, password: str) -> bool:
        """
        Verify user password.
        
        Args:
            username: Username to verify
            password: Plain text password to check
            
        Returns:
            True if password is correct
        """
        user = self.users.get(username)
        if not user:
            return False
        
        return pwd_context.verify(password, user.password_hash)
    
    def is_rate_limited(self, ip_address: str) -> bool:
        """
        Check if IP is rate limited.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if rate limited
        """
        # clean old attempts
        current_time = time.time()
        self.auth_attempts = [
            attempt for attempt in self.auth_attempts
            if current_time - attempt.timestamp < self.window_seconds
        ]
        
        # count recent attempts from this ip
        recent_attempts = [
            attempt for attempt in self.auth_attempts
            if attempt.ip_address == ip_address and not attempt.success
        ]
        
        return len(recent_attempts) >= self.max_attempts
    
    def record_attempt(
        self,
        ip_address: str,
        username: Optional[str],
        success: bool
    ):
        """
        Record authentication attempt.
        
        Args:
            ip_address: Client IP address
            username: Username attempted
            success: Whether attempt succeeded
        """
        self.auth_attempts.append(AuthAttempt(
            ip_address=ip_address,
            timestamp=time.time(),
            success=success,
            username=username
        ))
        
        # keep only recent attempts to prevent memory growth
        if len(self.auth_attempts) > 1000:
            current_time = time.time()
            self.auth_attempts = [
                attempt for attempt in self.auth_attempts
                if current_time - attempt.timestamp < self.window_seconds
            ]
    
    def authenticate(
        self,
        username: str,
        password: str,
        ip_address: str
    ) -> tuple[bool, str]:
        """
        Authenticate a user.
        
        Args:
            username: Username to authenticate
            password: Password to verify
            ip_address: Client IP address
            
        Returns:
            Tuple of (success, message)
        """
        # check rate limiting
        if self.is_rate_limited(ip_address):
            logger.warning("authentication rate limited", ip=ip_address)
            return False, "Too many failed attempts. Please try again later."
        
        # verify user exists
        user = self.users.get(username)
        if not user:
            self.record_attempt(ip_address, username, False)
            logger.warning("authentication failed - user not found", username=username)
            return False, "Invalid username or password"
        
        # check if user is enabled
        if not user.enabled:
            self.record_attempt(ip_address, username, False)
            logger.warning("authentication failed - user disabled", username=username)
            return False, "Account is disabled"
        
        # verify password
        if not self.verify_password(username, password):
            self.record_attempt(ip_address, username, False)
            logger.warning("authentication failed - wrong password", username=username)
            return False, "Invalid username or password"
        
        # check max sessions
        active_sessions = [
            session for session, user in self.active_sessions.items()
            if user == username
        ]
        if len(active_sessions) >= user.max_sessions:
            self.record_attempt(ip_address, username, False)
            logger.warning("authentication failed - max sessions", username=username)
            return False, "Maximum sessions reached for this user"
        
        # authentication successful
        self.record_attempt(ip_address, username, True)
        logger.info("authentication successful", username=username, ip=ip_address)
        return True, "Authentication successful"
    
    def create_session(self, username: str, session_token: str):
        """
        Create user session.
        
        Args:
            username: Username for session
            session_token: Generated session token
        """
        self.active_sessions[session_token] = username
        logger.info("created session", username=username)
    
    def remove_session(self, session_token: str):
        """
        Remove user session.
        
        Args:
            session_token: Session token to remove
        """
        username = self.active_sessions.pop(session_token, None)
        if username:
            logger.info("removed session", username=username)
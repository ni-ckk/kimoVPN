"""
Client Configuration Module

Manages client settings using Pydantic for validation.
"""

from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, validator
from functools import lru_cache


class ClientSettings(BaseSettings):
    """Client application settings with validation."""
    
    # server configuration
    SERVER_HOST: str = Field(default="85.215.205.80", description="VPN server IP address")
    SERVER_PORT: int = Field(default=13337, ge=1, le=65535, description="VPN server port")
    
    # authentication
    VPN_USERNAME: str = Field(..., description="VPN username")
    VPN_PASSWORD: str = Field(..., description="VPN password")
    
    # web UI configuration  
    WEB_UI_HOST: str = Field(default="127.0.0.1", description="Web UI host")
    WEB_UI_PORT: int = Field(default=5000, description="Web UI port")
    WEB_UI_AUTO_LAUNCH: bool = Field(default=True, description="Auto-launch browser on startup")
    
    # connection settings
    CONNECTION_TIMEOUT: int = Field(default=30, ge=5, description="Connection timeout in seconds")
    RETRY_ATTEMPTS: int = Field(default=3, ge=1, description="Number of retry attempts")
    AUTO_RECONNECT: bool = Field(default=False, description="Auto-reconnect on disconnect")
    
    # security settings
    SSL_VERIFY: bool = Field(default=True, description="Verify SSL certificates")
    KILL_SWITCH_ENABLED: bool = Field(default=True, description="Enable kill switch")
    
    # logging
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")
    LOG_FILE: Optional[str] = Field(default=None, description="Log file path")
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )
    
    @validator("LOG_LEVEL")
    def validate_log_level(cls, v: str) -> str:
        """Validate log level is valid."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        v = v.upper()
        if v not in valid_levels:
            raise ValueError(f"Log level must be one of {valid_levels}")
        return v


@lru_cache()
def get_settings() -> ClientSettings:
    """Get cached settings instance."""
    return ClientSettings()
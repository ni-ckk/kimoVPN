"""
Performance metrics collection for VPN.

This module tracks and reports various performance metrics
including bandwidth, latency, packet loss, and connection stats.
"""

import time
import threading
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from collections import deque

from pydantic import BaseModel, Field

from src.common.logging import get_logger

logger = get_logger(__name__)


@dataclass
class BandwidthMetrics:
    """Tracks bandwidth usage over time."""
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    start_time: float = field(default_factory=time.time)
    last_update: float = field(default_factory=time.time)
    
    def update_sent(self, bytes_count: int, packet_count: int = 1):
        """Update sent metrics."""
        self.bytes_sent += bytes_count
        self.packets_sent += packet_count
        self.last_update = time.time()
    
    def update_received(self, bytes_count: int, packet_count: int = 1):
        """Update received metrics."""
        self.bytes_received += bytes_count
        self.packets_received += packet_count
        self.last_update = time.time()
    
    def get_duration(self) -> float:
        """Get duration in seconds."""
        return time.time() - self.start_time
    
    def get_throughput(self) -> Dict[str, float]:
        """Calculate throughput in Mbps."""
        duration = self.get_duration()
        if duration == 0:
            return {"upload_mbps": 0, "download_mbps": 0}
        
        return {
            "upload_mbps": (self.bytes_sent * 8) / (duration * 1000000),
            "download_mbps": (self.bytes_received * 8) / (duration * 1000000)
        }
    
    def get_packet_rate(self) -> Dict[str, float]:
        """Calculate packet rate per second."""
        duration = self.get_duration()
        if duration == 0:
            return {"sent_pps": 0, "received_pps": 0}
        
        return {
            "sent_pps": self.packets_sent / duration,
            "received_pps": self.packets_received / duration
        }


class LatencyTracker:
    """Tracks latency measurements."""
    
    def __init__(self, window_size: int = 100):
        """
        Initialize latency tracker.
        
        Args:
            window_size: Size of rolling window for stats
        """
        self.window_size = window_size
        self.latencies: deque = deque(maxlen=window_size)
        self.lock = threading.Lock()
    
    def add_measurement(self, latency_ms: float):
        """Add latency measurement in milliseconds."""
        with self.lock:
            self.latencies.append(latency_ms)
    
    def get_stats(self) -> Dict[str, float]:
        """Get latency statistics."""
        with self.lock:
            if not self.latencies:
                return {
                    "min_ms": 0,
                    "max_ms": 0,
                    "avg_ms": 0,
                    "jitter_ms": 0,
                    "samples": 0
                }
            
            latencies_list = list(self.latencies)
            avg = sum(latencies_list) / len(latencies_list)
            
            # calculate jitter (average deviation from mean)
            jitter = 0
            if len(latencies_list) > 1:
                deviations = [abs(l - avg) for l in latencies_list]
                jitter = sum(deviations) / len(deviations)
            
            return {
                "min_ms": min(latencies_list),
                "max_ms": max(latencies_list),
                "avg_ms": avg,
                "jitter_ms": jitter,
                "samples": len(latencies_list)
            }


class PacketLossTracker:
    """Tracks packet loss statistics."""
    
    def __init__(self):
        """Initialize packet loss tracker."""
        self.sent_sequences: Dict[int, float] = {}  # sequence -> timestamp
        self.received_sequences: set = set()
        self.lock = threading.Lock()
        self.timeout = 10.0  # timeout for considering packet lost
    
    def mark_sent(self, sequence: int):
        """Mark packet as sent."""
        with self.lock:
            self.sent_sequences[sequence] = time.time()
    
    def mark_received(self, sequence: int):
        """Mark packet as received."""
        with self.lock:
            self.received_sequences.add(sequence)
    
    def get_loss_rate(self) -> Dict[str, Any]:
        """Calculate packet loss rate."""
        with self.lock:
            current_time = time.time()
            
            # identify lost packets (timed out and not received)
            lost_count = 0
            total_sent = len(self.sent_sequences)
            
            for seq, timestamp in list(self.sent_sequences.items()):
                if current_time - timestamp > self.timeout:
                    if seq not in self.received_sequences:
                        lost_count += 1
                    # clean up old entries
                    del self.sent_sequences[seq]
                    self.received_sequences.discard(seq)
            
            loss_rate = 0
            if total_sent > 0:
                loss_rate = (lost_count / total_sent) * 100
            
            return {
                "sent": total_sent,
                "lost": lost_count,
                "loss_percent": loss_rate,
                "pending": len(self.sent_sequences)
            }


class ConnectionMetrics(BaseModel):
    """Overall connection metrics."""
    connection_start: float = Field(default_factory=time.time)
    connection_status: str = "disconnected"
    uptime_seconds: float = 0
    reconnect_count: int = 0
    error_count: int = 0
    last_error: Optional[str] = None
    
    def update_status(self, status: str):
        """Update connection status."""
        self.connection_status = status
        if status == "connected":
            self.uptime_seconds = time.time() - self.connection_start
    
    def record_error(self, error_msg: str):
        """Record connection error."""
        self.error_count += 1
        self.last_error = error_msg
    
    def record_reconnect(self):
        """Record reconnection."""
        self.reconnect_count += 1
        self.connection_start = time.time()


class MetricsCollector:
    """Central metrics collection and reporting."""
    
    def __init__(self):
        """Initialize metrics collector."""
        self.bandwidth = BandwidthMetrics()
        self.latency = LatencyTracker()
        self.packet_loss = PacketLossTracker()
        self.connection = ConnectionMetrics()
        
        # periodic metrics
        self.periodic_metrics: List[BandwidthMetrics] = []
        self.current_period_start = time.time()
        self.period_duration = 60  # 1 minute periods
        
        self.lock = threading.Lock()
        
        logger.info("metrics collector initialized")
    
    def record_packet_sent(self, bytes_count: int, sequence: Optional[int] = None):
        """Record outgoing packet."""
        with self.lock:
            self.bandwidth.update_sent(bytes_count)
            if sequence is not None:
                self.packet_loss.mark_sent(sequence)
    
    def record_packet_received(self, bytes_count: int, sequence: Optional[int] = None):
        """Record incoming packet."""
        with self.lock:
            self.bandwidth.update_received(bytes_count)
            if sequence is not None:
                self.packet_loss.mark_received(sequence)
    
    def record_latency(self, latency_ms: float):
        """Record latency measurement."""
        self.latency.add_measurement(latency_ms)
    
    def update_connection_status(self, status: str):
        """Update connection status."""
        with self.lock:
            self.connection.update_status(status)
    
    def record_error(self, error_msg: str):
        """Record error."""
        with self.lock:
            self.connection.record_error(error_msg)
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """Get current metrics snapshot."""
        with self.lock:
            # check if we should rotate period
            if time.time() - self.current_period_start > self.period_duration:
                self._rotate_period()
            
            throughput = self.bandwidth.get_throughput()
            packet_rate = self.bandwidth.get_packet_rate()
            
            return {
                "bandwidth": {
                    "bytes_sent": self.bandwidth.bytes_sent,
                    "bytes_received": self.bandwidth.bytes_received,
                    "packets_sent": self.bandwidth.packets_sent,
                    "packets_received": self.bandwidth.packets_received,
                    **throughput,
                    **packet_rate
                },
                "latency": self.latency.get_stats(),
                "packet_loss": self.packet_loss.get_loss_rate(),
                "connection": self.connection.dict(),
                "collection_time": time.time()
            }
    
    def get_historical_metrics(self) -> List[Dict[str, Any]]:
        """Get historical metrics by period."""
        with self.lock:
            return [
                {
                    "period_start": metrics.start_time,
                    "duration": metrics.get_duration(),
                    **metrics.get_throughput(),
                    **metrics.get_packet_rate(),
                    "bytes_sent": metrics.bytes_sent,
                    "bytes_received": metrics.bytes_received
                }
                for metrics in self.periodic_metrics[-10:]  # last 10 periods
            ]
    
    def _rotate_period(self):
        """Rotate to new metrics period."""
        # save current period
        if self.bandwidth.bytes_sent > 0 or self.bandwidth.bytes_received > 0:
            self.periodic_metrics.append(self.bandwidth)
            
            # keep only last 60 periods (1 hour at 1 minute periods)
            if len(self.periodic_metrics) > 60:
                self.periodic_metrics.pop(0)
        
        # start new period
        self.bandwidth = BandwidthMetrics()
        self.current_period_start = time.time()
    
    def reset(self):
        """Reset all metrics."""
        with self.lock:
            self.bandwidth = BandwidthMetrics()
            self.latency = LatencyTracker()
            self.packet_loss = PacketLossTracker()
            self.connection = ConnectionMetrics()
            self.periodic_metrics.clear()
            self.current_period_start = time.time()
            
            logger.info("metrics reset")


class MetricsReporter:
    """Formats and reports metrics."""
    
    @staticmethod
    def format_bandwidth(metrics: Dict[str, Any]) -> str:
        """Format bandwidth metrics as string."""
        bw = metrics.get("bandwidth", {})
        return (
            f"↑ {bw.get('upload_mbps', 0):.2f} Mbps "
            f"({bw.get('sent_pps', 0):.0f} pps) | "
            f"↓ {bw.get('download_mbps', 0):.2f} Mbps "
            f"({bw.get('received_pps', 0):.0f} pps)"
        )
    
    @staticmethod
    def format_latency(metrics: Dict[str, Any]) -> str:
        """Format latency metrics as string."""
        lat = metrics.get("latency", {})
        return (
            f"Latency: {lat.get('avg_ms', 0):.1f}ms "
            f"(min: {lat.get('min_ms', 0):.1f}, "
            f"max: {lat.get('max_ms', 0):.1f}, "
            f"jitter: {lat.get('jitter_ms', 0):.1f})"
        )
    
    @staticmethod
    def format_packet_loss(metrics: Dict[str, Any]) -> str:
        """Format packet loss metrics as string."""
        loss = metrics.get("packet_loss", {})
        return (
            f"Packet Loss: {loss.get('loss_percent', 0):.1f}% "
            f"({loss.get('lost', 0)}/{loss.get('sent', 0)})"
        )
    
    @staticmethod
    def format_connection(metrics: Dict[str, Any]) -> str:
        """Format connection metrics as string."""
        conn = metrics.get("connection", {})
        uptime = conn.get("uptime_seconds", 0)
        hours = int(uptime // 3600)
        minutes = int((uptime % 3600) // 60)
        seconds = int(uptime % 60)
        
        return (
            f"Status: {conn.get('connection_status', 'unknown')} | "
            f"Uptime: {hours:02d}:{minutes:02d}:{seconds:02d} | "
            f"Errors: {conn.get('error_count', 0)}"
        )
    
    @staticmethod
    def print_summary(metrics: Dict[str, Any]):
        """Print formatted metrics summary."""
        print("\n=== VPN Performance Metrics ===")
        print(MetricsReporter.format_connection(metrics))
        print(MetricsReporter.format_bandwidth(metrics))
        print(MetricsReporter.format_latency(metrics))
        print(MetricsReporter.format_packet_loss(metrics))
        print("=" * 30)
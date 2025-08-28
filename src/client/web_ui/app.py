"""
Flask Web UI Application

Provides web interface for VPN client control.
"""

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from typing import Optional, List, Dict, Any
from datetime import datetime
import threading
import structlog
from ..connection import VPNConnection, ConnectionConfig
from ..config import get_settings
from ...common.models import ConnectionStatus, ConnectionStats

logger = structlog.get_logger()

# initialize flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key'  # change in production

# configure cors for rest api
CORS(app, resources={r"/api/*": {"origins": "*"}})

# configure socketio with cors
socketio = SocketIO(app, cors_allowed_origins="*")

# global vpn connection instance
vpn_connection: Optional[VPNConnection] = None
connection_status = ConnectionStatus.DISCONNECTED
connection_stats = ConnectionStats(status=ConnectionStatus.DISCONNECTED)
connection_history: List[Dict[str, Any]] = []
auto_reconnect_enabled = False
config_overrides: Dict[str, Any] = {}


@app.route('/')
def index():
    """Serve the main web UI page."""
    return render_template('index.html')


@app.route('/api/status', methods=['GET'])
def get_status():
    """Get current VPN connection status."""
    global connection_stats
    
    # update stats from vpn connection if available
    if vpn_connection and vpn_connection.status == ConnectionStatus.CONNECTED:
        _update_stats_from_connection()
    
    return jsonify({
        'status': connection_status.value,
        'stats': connection_stats.model_dump(mode='json'),
        'auto_reconnect': auto_reconnect_enabled
    })


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get detailed connection statistics."""
    global connection_stats
    
    # update stats from vpn connection if available
    if vpn_connection and vpn_connection.status == ConnectionStatus.CONNECTED:
        _update_stats_from_connection()
    
    return jsonify(connection_stats.model_dump(mode='json'))


@app.route('/api/connect', methods=['POST'])
def connect():
    """Initiate VPN connection."""
    global vpn_connection, connection_status
    
    if connection_status != ConnectionStatus.DISCONNECTED:
        return jsonify({'success': False, 'message': 'Already connected or connecting'}), 400
    
    try:
        settings = get_settings()
        
        # use overrides if available, otherwise use settings
        config = ConnectionConfig(
            server_host=config_overrides.get('server_host', settings.SERVER_HOST),
            server_port=config_overrides.get('server_port', settings.SERVER_PORT),
            username=config_overrides.get('username', settings.VPN_USERNAME),
            password=config_overrides.get('password', settings.VPN_PASSWORD),
            ssl_verify=config_overrides.get('ssl_verify', settings.SSL_VERIFY),
            connection_timeout=settings.CONNECTION_TIMEOUT,
            retry_attempts=settings.RETRY_ATTEMPTS
        )
        
        connection_status = ConnectionStatus.CONNECTING
        socketio.emit('status_update', {'status': connection_status.value})
        
        # create connection in background thread
        vpn_connection = VPNConnection(config)
        thread = threading.Thread(target=_connect_background)
        thread.start()
        
        return jsonify({'success': True, 'message': 'Connection initiated'})
        
    except Exception as e:
        logger.error("failed to initiate connection", error=str(e))
        connection_status = ConnectionStatus.ERROR
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/config', methods=['GET'])
def get_config():
    """Get current configuration."""
    try:
        settings = get_settings()
        return jsonify({
            'server_host': config_overrides.get('server_host', settings.SERVER_HOST),
            'server_port': config_overrides.get('server_port', settings.SERVER_PORT),
            'username': config_overrides.get('username', settings.VPN_USERNAME),
            'ssl_verify': config_overrides.get('ssl_verify', settings.SSL_VERIFY),
            'auto_reconnect': auto_reconnect_enabled,
            'connection_timeout': settings.CONNECTION_TIMEOUT,
            'retry_attempts': settings.RETRY_ATTEMPTS
        })
    except Exception as e:
        logger.error("failed to get config", error=str(e))
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/config', methods=['POST'])
def update_config():
    """Update configuration."""
    global config_overrides, auto_reconnect_enabled
    
    try:
        data = request.get_json()
        
        # update config overrides
        if 'server_host' in data:
            config_overrides['server_host'] = data['server_host']
        if 'server_port' in data:
            config_overrides['server_port'] = data['server_port']
        if 'username' in data:
            config_overrides['username'] = data['username']
        if 'password' in data:
            config_overrides['password'] = data['password']
        if 'ssl_verify' in data:
            config_overrides['ssl_verify'] = data['ssl_verify']
        if 'auto_reconnect' in data:
            auto_reconnect_enabled = data['auto_reconnect']
        
        logger.info("config updated", updates=data)
        return jsonify({'success': True, 'message': 'Configuration updated'})
        
    except Exception as e:
        logger.error("failed to update config", error=str(e))
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/history', methods=['GET'])
def get_history():
    """Get connection history."""
    return jsonify({'history': connection_history[-50:]})  # last 50 entries


@app.route('/api/disconnect', methods=['POST'])
def disconnect():
    """Disconnect from VPN."""
    global vpn_connection, connection_status, connection_history
    
    if connection_status not in [ConnectionStatus.CONNECTED, ConnectionStatus.CONNECTING]:
        return jsonify({'success': False, 'message': 'Not connected'}), 400
    
    try:
        connection_status = ConnectionStatus.DISCONNECTING
        socketio.emit('status_update', {'status': connection_status.value})
        
        if vpn_connection:
            vpn_connection.disconnect()
            vpn_connection = None
            
        connection_status = ConnectionStatus.DISCONNECTED
        socketio.emit('status_update', {'status': connection_status.value})
        
        # add to history
        connection_history.append({
            'timestamp': datetime.now().isoformat(),
            'event': 'disconnected',
            'reason': 'user_requested'
        })
        
        return jsonify({'success': True, 'message': 'Disconnected successfully'})
        
    except Exception as e:
        logger.error("failed to disconnect", error=str(e))
        return jsonify({'success': False, 'message': str(e)}), 500


def _connect_background():
    """Background thread for VPN connection."""
    global connection_status, connection_history
    
    start_time = datetime.now()
    
    try:
        if vpn_connection and vpn_connection.connect():
            connection_status = ConnectionStatus.CONNECTED
            logger.info("vpn connection established")
            
            # add to history
            connection_history.append({
                'timestamp': start_time.isoformat(),
                'event': 'connected',
                'server': vpn_connection.config.server_host,
                'virtual_ip': vpn_connection.virtual_ip
            })
            
            # start monitoring stats
            _start_stats_monitor()
        else:
            connection_status = ConnectionStatus.ERROR
            logger.error("vpn connection failed")
            
            # add failure to history
            connection_history.append({
                'timestamp': start_time.isoformat(),
                'event': 'connection_failed',
                'server': vpn_connection.config.server_host if vpn_connection else 'unknown'
            })
            
            # check auto-reconnect
            if auto_reconnect_enabled:
                threading.Timer(5.0, _attempt_reconnect).start()
            
    except Exception as e:
        logger.error("connection error", error=str(e))
        connection_status = ConnectionStatus.ERROR
        
        # add error to history
        connection_history.append({
            'timestamp': start_time.isoformat(),
            'event': 'connection_error',
            'error': str(e)
        })
        
    finally:
        socketio.emit('status_update', {'status': connection_status.value})


@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection."""
    logger.info("websocket client connected")
    emit('status_update', {'status': connection_status.value})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection."""
    logger.info("websocket client disconnected")


def _update_stats_from_connection():
    """Update stats from the VPN connection."""
    global connection_stats
    
    if not vpn_connection:
        return
    
    # get comprehensive stats from vpn connection
    if hasattr(vpn_connection, 'get_connection_stats'):
        vpn_stats = vpn_connection.get_connection_stats()
        connection_stats.bytes_sent = vpn_stats.get('bytes_sent', 0)
        connection_stats.bytes_received = vpn_stats.get('bytes_received', 0)
        connection_stats.packets_sent = vpn_stats.get('packets_sent', 0)
        connection_stats.packets_received = vpn_stats.get('packets_received', 0)
        connection_stats.current_latency_ms = vpn_stats.get('current_latency_ms')
        connection_stats.average_latency_ms = vpn_stats.get('average_latency_ms')


def _start_stats_monitor():
    """Start monitoring connection statistics."""
    def monitor():
        while connection_status == ConnectionStatus.CONNECTED:
            _update_stats_from_connection()
            socketio.emit('stats_update', connection_stats.model_dump(mode='json'))
            threading.Event().wait(2)  # update every 2 seconds
    
    thread = threading.Thread(target=monitor, daemon=True)
    thread.start()


def _attempt_reconnect():
    """Attempt to reconnect if auto-reconnect is enabled."""
    global vpn_connection, connection_status
    
    if auto_reconnect_enabled and connection_status in [ConnectionStatus.ERROR, ConnectionStatus.DISCONNECTED]:
        logger.info("attempting auto-reconnect")
        
        try:
            settings = get_settings()
            config = ConnectionConfig(
                server_host=config_overrides.get('server_host', settings.SERVER_HOST),
                server_port=config_overrides.get('server_port', settings.SERVER_PORT),
                username=config_overrides.get('username', settings.VPN_USERNAME),
                password=config_overrides.get('password', settings.VPN_PASSWORD),
                ssl_verify=config_overrides.get('ssl_verify', settings.SSL_VERIFY),
                connection_timeout=settings.CONNECTION_TIMEOUT,
                retry_attempts=settings.RETRY_ATTEMPTS
            )
            
            connection_status = ConnectionStatus.CONNECTING
            socketio.emit('status_update', {'status': connection_status.value})
            
            vpn_connection = VPNConnection(config)
            thread = threading.Thread(target=_connect_background)
            thread.start()
            
        except Exception as e:
            logger.error("auto-reconnect failed", error=str(e))


def run_web_ui(host: str = '127.0.0.1', port: int = 5000, debug: bool = False):
    """
    Run the Flask web UI server.
    
    Args:
        host: Host to bind to
        port: Port to bind to
        debug: Enable debug mode
    """
    socketio.run(app, host=host, port=port, debug=debug)
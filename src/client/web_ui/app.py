"""
Flask Web UI Application

Provides web interface for VPN client control.
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from typing import Optional
import threading
import structlog
from ..connection import VPNConnection, ConnectionConfig
from ..config import get_settings
from ...common.models import ConnectionStatus, ConnectionStats

logger = structlog.get_logger()

# initialize flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key'  # change in production
socketio = SocketIO(app, cors_allowed_origins="*")

# global vpn connection instance
vpn_connection: Optional[VPNConnection] = None
connection_status = ConnectionStatus.DISCONNECTED
connection_stats = ConnectionStats(status=ConnectionStatus.DISCONNECTED)


@app.route('/')
def index():
    """Serve the main web UI page."""
    return render_template('index.html')


@app.route('/api/status', methods=['GET'])
def get_status():
    """Get current VPN connection status."""
    return jsonify({
        'status': connection_status.value,
        'stats': connection_stats.model_dump(mode='json')
    })


@app.route('/api/connect', methods=['POST'])
def connect():
    """Initiate VPN connection."""
    global vpn_connection, connection_status
    
    if connection_status != ConnectionStatus.DISCONNECTED:
        return jsonify({'success': False, 'message': 'Already connected or connecting'}), 400
    
    try:
        settings = get_settings()
        config = ConnectionConfig(
            server_host=settings.SERVER_HOST,
            server_port=settings.SERVER_PORT,
            username=settings.VPN_USERNAME,
            password=settings.VPN_PASSWORD,
            ssl_verify=settings.SSL_VERIFY,
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


@app.route('/api/disconnect', methods=['POST'])
def disconnect():
    """Disconnect from VPN."""
    global vpn_connection, connection_status
    
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
        
        return jsonify({'success': True, 'message': 'Disconnected successfully'})
        
    except Exception as e:
        logger.error("failed to disconnect", error=str(e))
        return jsonify({'success': False, 'message': str(e)}), 500


def _connect_background():
    """Background thread for VPN connection."""
    global connection_status
    
    try:
        if vpn_connection and vpn_connection.connect():
            connection_status = ConnectionStatus.CONNECTED
            logger.info("vpn connection established")
        else:
            connection_status = ConnectionStatus.ERROR
            logger.error("vpn connection failed")
            
    except Exception as e:
        logger.error("connection error", error=str(e))
        connection_status = ConnectionStatus.ERROR
        
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


def run_web_ui(host: str = '127.0.0.1', port: int = 5000, debug: bool = False):
    """
    Run the Flask web UI server.
    
    Args:
        host: Host to bind to
        port: Port to bind to
        debug: Enable debug mode
    """
    socketio.run(app, host=host, port=port, debug=debug)
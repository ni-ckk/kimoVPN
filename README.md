# kimoVPN

## Overview

kimoVPN is an private project that demonstrates secure networking concepts through a custom VPN implementation. It features end-to-end encryption, web-based client control, and a fail-secure kill switch mechanism.

![kimoVPN Web UI](https://github.com/user-attachments/assets/kimovpn-ui-screenshot-3.png)


## Features

- **Secure Connection**: TLS/SSL with PyNaCl encryption
- **Web UI Control Panel**: Modern web interface for VPN management
- **Kill Switch (TBA)**: Fail-secure mechanism to prevent data leaks
- **Real-time Status**: WebSocket-based status updates
- **Cross-platform**: Windows client, Linux server
- **Easy Distribution**: Single executable for Windows

## Quick Start

### Local Development (Windows)

For quick local testing on Windows:

```bash
# Terminal 1: Start server
cd kimoVPN
source .venv/Scripts/activate
python -m src.server.main

# Terminal 2: Start client
cd kimoVPN
source .venv/Scripts/activate
python -m src.client.main --local
```

The `--local` flag automatically:
- Disables SSL verification (for self-signed certificates)
- Uses localhost (127.0.0.1) as server
- Uses test credentials (testuser/testpass123)

### Prerequisites

- Python 3.9 or higher
- UV package manager ([install UV](https://github.com/astral-sh/uv))
- Git Bash (for Windows development)
- Linux VPS for server deployment (Ubuntu/Debian recommended)

### Client Setup (Windows)

1. **Clone the repository**:
```bash
git clone https://github.com/ni-ckk/kimoVPN.git
cd kimoVPN
```

2. **Install UV** (if not already installed):
```bash
# Windows (PowerShell as Admin)
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"

# Or using pip
pip install uv
```

3. **Create virtual environment and install dependencies**:
```bash
# Create .venv in project root (NOT in src/)
uv venv
source .venv/Scripts/activate  # On Windows Git Bash
# source .venv/bin/activate     # On Linux/Mac

# Install dependencies
uv sync
```

4. **Configure environment**:
```bash
cp .env.example .env
# Edit .env with your server details and credentials
```

5. **Run the client**:
```bash
# For local development/testing (Windows)
python -m src.client.main --local
# This automatically uses localhost, test credentials, and disables SSL verification

# Or specify options manually
python -m src.client.main --no-verify --username testuser --password testpass123

# Web UI will automatically open at http://127.0.0.1:5000
```

### Server Setup (Linux VPS)

1. **SSH into your VPS**:
```bash
ssh user@85.215.205.80
```

2. **Clone and setup**:
```bash
git clone https://github.com/ni-ckk/kimoVPN.git
cd kimoVPN
python3 -m pip install uv
uv venv
source .venv/bin/activate
uv sync
```

3. **Configure server**:
```bash
sudo mkdir -p /etc/kimovpn
sudo cp .env.example /etc/kimovpn/.env
# Edit /etc/kimovpn/.env with server configuration
```

4. **Generate SSL certificates**:
```bash
# Self-signed for testing (use Let's Encrypt for production)
sudo openssl req -x509 -newkey rsa:4096 -keyout /etc/kimovpn/server.key \
  -out /etc/kimovpn/server.crt -days 365 -nodes
```

5. **Configure networking**:
```bash
# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

# Configure iptables for NAT
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i tun0 -j ACCEPT
sudo iptables -A FORWARD -o tun0 -j ACCEPT
```

6. **Run the server**:
```bash
sudo python -m src.server.main
```

## Building Executable (Windows)

Create a standalone Windows executable:

```bash
# Activate virtual environment
source .venv/Scripts/activate

# Build with PyInstaller
python scripts/build.py

# Output will be in dist/kimoVPN.exe
```

## Project Structure

```
kimoVPN/
├── src/
│   ├── client/         # VPN client implementation
│   ├── server/         # VPN server implementation
│   └── common/         # Shared utilities and models
├── tests/              # Test suites
├── docs/               # Documentation
├── scripts/            # Build and deployment scripts
└── web_ui/            # Web interface assets
```

## Configuration

All configuration is done through environment variables. See `.env.example` for available options.

Key settings:
- `SERVER_HOST`: VPN server IP address
- `SERVER_PORT`: VPN server port (default: 13337)
- `VPN_USERNAME/PASSWORD`: Authentication credentials
- `KILL_SWITCH_ENABLED`: Enable/disable kill switch
- `LOG_LEVEL`: Logging verbosity (DEBUG, INFO, WARNING, ERROR)

## Testing

Run the test suite:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src tests/

# Run specific test file
pytest tests/test_client/test_connection.py
```

## Development Workflow

1. **Check plan.md** for detailed implementation phases
2. **Follow CLAUDE.md** for coding standards and principles
3. **Use UV** for dependency management
4. **Run tests** before committing changes
5. **Update documentation** as you develop

## Security Considerations

- Uses established cryptographic libraries (PyNaCl/libsodium)
- Implements defense-in-depth principles
- Includes fail-secure kill switch mechanism
- Passwords hashed with bcrypt
- Rate limiting on authentication attempts
- All traffic encrypted end-to-end

## License

This project is for educational purposes. See LICENSE file for details.

## Contributing

This is a portfolio project, but suggestions and security reviews are welcome:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

## Documentation

- [Implementation Plan](plan.md) - Detailed development phases
- [Protocol Specification](docs/protocol.md) - VPN protocol details
- [Security Analysis](docs/security.md) - Security considerations
- [Deployment Guide](docs/deployment.md) - Production deployment

## Disclaimer

This VPN implementation is created for educational and portfolio purposes. It demonstrates understanding of:
- Network security concepts
- Cryptographic implementations
- Client-server architecture
- Modern web UI development
- Software packaging and distribution

**Do not use in production environments without proper security audit and testing.**

## Support

For questions or issues:
- Open an issue on [GitHub](https://github.com/ni-ckk/kimoVPN/issues)
- Check existing documentation in `/docs`
- Review the implementation plan in `plan.md`

---

*Built with focus on security, simplicity, and educational value.*
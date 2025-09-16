# Certificate Directory

This directory contains SSL/TLS certificates for the VPN connection.

**IMPORTANT**: Never commit actual certificates or private keys to version control!

## Required Files

For local testing, you need to generate the following files:

- `ca.crt` - Certificate Authority certificate
- `ca.key` - Certificate Authority private key
- `server.crt` - Server certificate
- `server.key` - Server private key  
- `client.crt` - Client certificate (optional, for mutual TLS)
- `client.key` - Client private key (optional)

## Generating Certificates

Run the certificate generation script:

```bash
python scripts/generate_certs.py
```

This will create self-signed certificates suitable for local development and testing.

## Production Deployment

For production use:
- Use certificates from a trusted Certificate Authority (e.g., Let's Encrypt)
- Store certificates securely on the server
- Never share private keys
- Use proper file permissions (600 or 400)

## Security Notes

- The `.gitignore` file is configured to exclude all certificates and keys
- Generated certificates are for TESTING ONLY
- Private keys should never leave the machine they were generated on
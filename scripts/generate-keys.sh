#!/bin/bash

# Script to generate RSA key pair for CSRF token signing
# Usage: ./generate-keys.sh [output-directory]

OUTPUT_DIR=${1:-.}
PRIVATE_KEY="$OUTPUT_DIR/csrf-private-key.pem"
PUBLIC_KEY="$OUTPUT_DIR/csrf-public-key.pem"

echo "🔐 Generating RSA key pair for CSRF protection..."
echo ""

# Check if openssl is installed
if ! command -v openssl &> /dev/null; then
    echo "❌ Error: openssl is not installed"
    echo "Please install openssl first:"
    echo "  - Ubuntu/Debian: sudo apt-get install openssl"
    echo "  - macOS: brew install openssl"
    echo "  - Windows: Download from https://slproweb.com/products/Win32OpenSSL.html"
    exit 1
fi

# Generate private key
echo "📝 Generating private key..."
openssl genrsa -out "$PRIVATE_KEY" 2048

if [ $? -ne 0 ]; then
    echo "❌ Failed to generate private key"
    exit 1
fi

echo "✅ Private key generated: $PRIVATE_KEY"

# Extract public key
echo "📝 Extracting public key..."
openssl rsa -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"

if [ $? -ne 0 ]; then
    echo "❌ Failed to extract public key"
    exit 1
fi

echo "✅ Public key generated: $PUBLIC_KEY"
echo ""
echo "🎉 Key pair generated successfully!"
echo ""
echo "⚠️  IMPORTANT SECURITY NOTES:"
echo "  1. NEVER commit the private key to version control"
echo "  2. Store the private key securely (vault, secrets manager)"
echo "  3. The private key should ONLY be on the token-issuing service"
echo "  4. The public key goes on the gateway (this project)"
echo "  5. Rotate keys periodically (recommended: every 90 days)"
echo ""
echo "📋 Next steps:"
echo "  1. Copy $PUBLIC_KEY to src/main/resources/keys/"
echo "  2. Securely transfer $PRIVATE_KEY to token-issuing service"
echo "  3. Delete $PRIVATE_KEY from this machine"
echo "  4. Update Confluence: Secure Store Inventory"
echo ""

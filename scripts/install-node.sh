#!/bin/bash
# One-liner node installer for 1ai-osint
# Usage: curl -sSL https://raw.githubusercontent.com/oyi77/1ai-osint/main/scripts/install-node.sh | bash -s -- --master http://5.189.138.144:8420 --id my-node
#
# Or with wget:
# wget -qO- https://raw.githubusercontent.com/oyi77/1ai-osint/main/scripts/install-node.sh | bash -s -- --master http://5.189.138.144:8420 --id my-node

set -e

# Parse arguments
MASTER_URL=""
NODE_ID=""
INSTALL_DIR="$HOME/1ai-osint"

while [[ $# -gt 0 ]]; do
    case $1 in
        --master) MASTER_URL="$2"; shift 2 ;;
        --id) NODE_ID="$2"; shift 2 ;;
        --dir) INSTALL_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Defaults
MASTER_URL="${MASTER_URL:-http://5.189.138.144:8420}"
NODE_ID="${NODE_ID:-node-$(hostname)-$(date +%s)}"

echo "=== 1ai-osint Node Installer ==="
echo "Master: $MASTER_URL"
echo "Node ID: $NODE_ID"
echo "Install dir: $INSTALL_DIR"
echo ""

# Check prerequisites
command -v git >/dev/null 2>&1 || { echo "Error: git not found. Install git first."; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "Error: python3 not found. Install Python 3.10+ first."; exit 1; }

# Clone or update repo
if [ -d "$INSTALL_DIR/.git" ]; then
    echo "Updating existing installation..."
    cd "$INSTALL_DIR"
    git pull
else
    echo "Cloning repository..."
    git clone https://github.com/oyi77/1ai-osint.git "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

# Create venv if needed
if [ ! -d "$INSTALL_DIR/.venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

# Install dependencies
echo "Installing dependencies..."
source .venv/bin/activate
pip install -e . -q 2>&1 | tail -3

# Create .env
if [ ! -f "$INSTALL_DIR/.env" ]; then
    cp .env.example .env
fi

# Add master API config to .env
grep -q "MASTER_API_URL" .env || echo "MASTER_API_URL=$MASTER_URL" >> .env
grep -q "NODE_ID" .env || echo "NODE_ID=$NODE_ID" >> .env

# Create systemd service
echo "Creating systemd service..."
sudo tee /etc/systemd/system/1ai-leak-finder.service > /dev/null << EOF
[Unit]
Description=1ai-osint Leak Finder ($NODE_ID)
After=network.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/.venv/bin/python -m src.cli leak-finder --sources all --continuous --interval 300
Restart=always
RestartSec=60
EnvironmentFile=$INSTALL_DIR/.env
MemoryMax=512M
MemoryHigh=384M
CPUQuota=50%

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable 1ai-leak-finder
sudo systemctl start 1ai-leak-finder

echo ""
echo "=== Installation Complete ==="
echo "Node ID: $NODE_ID"
echo "Master API: $MASTER_URL"
echo "Service: 1ai-leak-finder"
echo ""
echo "Check status: systemctl status 1ai-leak-finder"
echo "View logs: journalctl -u 1ai-leak-finder -f"
echo "Test connection: curl $MASTER_URL/api/health"

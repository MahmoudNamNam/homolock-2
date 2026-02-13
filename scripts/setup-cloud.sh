#!/usr/bin/env bash
# Run this on the EC2 instance (Ubuntu) to set up HomoLock-HR server.
# Usage: bash setup-cloud.sh [REPO_URL]
# Example: bash setup-cloud.sh https://github.com/you/Homolock.git
# If REPO_URL is omitted and ./server_py exists, only venv + deps are installed.

set -e
REPO_URL="${1:-}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/Homolock}"
DATA_DIR="${HOMOLOCK_DATA_DIR:-/var/lib/homolock}"

echo "=== HomoLock-HR cloud setup ==="

# System deps
sudo apt update
sudo apt install -y python3.10 python3.10-venv python3-pip git

# Clone or use current dir
if [ -n "$REPO_URL" ]; then
  mkdir -p "$(dirname "$INSTALL_DIR")"
  [ -d "$INSTALL_DIR" ] && { echo "Already exists: $INSTALL_DIR. Remove it or use another INSTALL_DIR."; exit 1; }
  git clone "$REPO_URL" "$INSTALL_DIR"
  cd "$INSTALL_DIR"
else
  if [ -d "server_py" ]; then
    cd "$(dirname "$0")/.."
  else
    echo "Either pass REPO_URL or run from repo root."
    exit 1
  fi
  INSTALL_DIR="$(pwd)"
fi

# Venv + Python deps
cd "$INSTALL_DIR/server_py"
python3.10 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Data dir
sudo mkdir -p "$DATA_DIR"
sudo chown "$USER:$USER" "$DATA_DIR"

echo ""
echo "Setup done. To run the server:"
echo "  cd $INSTALL_DIR/server_py"
echo "  source .venv/bin/activate"
echo "  export HOMOLOCK_DATA_DIR=$DATA_DIR"
echo "  uvicorn app.main:app --host 0.0.0.0 --port 8000"
echo ""
echo "Or use systemd (see README Deploy on EC2)."

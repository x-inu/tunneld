#!/usr/bin/env bash
# install.sh — Production installer for tunneld on Debian / Ubuntu hosts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== tunneld installer ==="

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Error: this installer must be run as root." >&2
    exit 1
fi

# 1. Check or install system package dependencies
echo "--> Checking system dependencies..."
PACKAGES=(
    "iproute2"
    "ppp"
    "xl2tpd"
    "sstp-client"
    "pptp-linux"
    "strongswan-swanctl"
    "curl"
    "ca-certificates"
)

MISSING=()
for pkg in "${PACKAGES[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        MISSING+=("$pkg")
    fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo "--> Installing missing packages: ${MISSING[*]}"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y --no-install-recommends "${MISSING[@]}"
else
    echo "    All required packages are already installed."
fi

# 2. Check /dev/ppp character device (major 108, minor 0)
echo "--> Checking /dev/ppp..."
if [[ ! -c /dev/ppp ]]; then
    echo "    /dev/ppp is missing. Attempting to create it..."
    if mknod /dev/ppp c 108 0 2>/dev/null; then
        chmod 600 /dev/ppp
        echo "    Created /dev/ppp successfully."
    else
        echo "    WARNING: Could not create /dev/ppp (permission denied in this container/LXC)."
        echo "    PPP tunnels (L2TP/SSTP/PPTP) will fail until /dev/ppp is exposed from the host."
        echo "    You can still run tunneld with -demo for UI evaluation."
    fi
fi

# 3. Disable conflicting system xl2tpd.service
echo "--> Checking system xl2tpd service..."
if systemctl is-active xl2tpd.service >/dev/null 2>&1; then
    echo "    Stopping and disabling system xl2tpd.service to free port 1701 for tunneld..."
    systemctl stop xl2tpd.service || true
    systemctl disable xl2tpd.service || true
fi

# 4. Build and install binary
echo "--> Installing /usr/local/bin/tunneld..."
if command -v go >/dev/null 2>&1 && [[ -d "${SOURCE_DIR}/cmd/tunneld" ]]; then
    echo "    Building tunneld from source in ${SOURCE_DIR}..."
    (cd "${SOURCE_DIR}" && go build -ldflags "-s -w -X main.version=0.1.0" -o /usr/local/bin/tunneld ./cmd/tunneld)
elif [[ -f "/tmp/opencode/tunneld" ]]; then
    echo "    Copying prebuilt binary from /tmp/opencode/tunneld..."
    cp -f /tmp/opencode/tunneld /usr/local/bin/tunneld
elif [[ -f "${SOURCE_DIR}/tunneld" ]]; then
    echo "    Copying binary from ${SOURCE_DIR}/tunneld..."
    cp -f "${SOURCE_DIR}/tunneld" /usr/local/bin/tunneld
else
    echo "Error: no Go compiler or prebuilt tunneld binary found." >&2
    exit 1
fi
chmod 755 /usr/local/bin/tunneld

# 5. Create directories
echo "--> Creating directories..."
mkdir -p /etc/tunneld
mkdir -p /var/lib/tunneld
mkdir -p /run/tunneld
mkdir -p /etc/swanctl/conf.d
chmod 700 /etc/tunneld /var/lib/tunneld /run/tunneld

# 6. Install configuration files if missing
echo "--> Checking configuration files in /etc/tunneld..."
if [[ ! -f /etc/tunneld/tunneld.yaml ]]; then
    echo "    Installing /etc/tunneld/tunneld.yaml from example..."
    cp "${SOURCE_DIR}/tunneld.yaml.example" /etc/tunneld/tunneld.yaml
    chmod 644 /etc/tunneld/tunneld.yaml
fi

if [[ ! -f /etc/tunneld/tunnels.yaml ]]; then
    echo "    Installing /etc/tunneld/tunnels.yaml from example..."
    cp "${SOURCE_DIR}/tunnels.yaml.example" /etc/tunneld/tunnels.yaml
    chmod 600 /etc/tunneld/tunnels.yaml
fi

if [[ ! -f /etc/tunneld/secrets.yaml ]]; then
    echo "    Installing /etc/tunneld/secrets.yaml with mode 0600..."
    cp "${SOURCE_DIR}/secrets.yaml.example" /etc/tunneld/secrets.yaml
    chmod 600 /etc/tunneld/secrets.yaml
    chown root:root /etc/tunneld/secrets.yaml
else
    chmod 600 /etc/tunneld/secrets.yaml
fi

# 7. Install systemd unit
echo "--> Installing systemd unit..."
cp "${SCRIPT_DIR}/tunneld.service" /etc/systemd/system/tunneld.service
systemctl daemon-reload

echo ""
echo "=== Installation complete ==="
echo "Binary:        /usr/local/bin/tunneld"
echo "Config dir:    /etc/tunneld"
echo "Database:      /var/lib/tunneld/tunneld.db"
echo "Systemd unit:  /etc/systemd/system/tunneld.service"
echo ""
echo "Next steps:"
echo "1. Set your administrator password hash in /etc/tunneld/tunneld.yaml:"
echo "   /usr/local/bin/tunneld hash-password"
echo ""
echo "2. Edit your tunnel definitions and credentials in:"
echo "   /etc/tunneld/tunnels.yaml"
echo "   /etc/tunneld/secrets.yaml (keep mode 0600)"
echo ""
echo "3. Start and enable the service:"
echo "   systemctl enable --now tunneld.service"
echo ""
echo "4. Access the dashboard locally at http://127.0.0.1:8095"
echo "   Or configure Nginx reverse proxy using ${SCRIPT_DIR}/nginx-tunneld.conf"

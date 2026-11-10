#!/usr/bin/env bash
# ==============================================================================
# Dyatel - Universal One-Click Game Proxy & NAT Traversal Installer
# ==============================================================================
# Standalone, zero-dependency installation script for Dyatel Gateway and Node.
# Supports WireGuard and AmneziaWG obfuscated transports.
#
# Usage:
#   Gateway Setup (VPS):
#     sudo ./install.sh --role gateway [options]
#
#   Node Setup (Home Server):
#     sudo ./install.sh --role node --endpoint <gateway:port> --server-key <pubkey>
#
# Options:
#   --role <gateway|node>       Target host role (mandatory)
#   --mode <wg|awg>             Transport mode (default: wg)
#   --game-port <port>          Game listening port (default: 25565)
#   --endpoint <host:port>      Gateway address for node connection
#   --server-key <key>          Public key of the gateway
#   --client-key <key>          Pre-generated client private key (optional)
#   --client-ip <ip/mask>       Client tunnel IPv4 address (default: 10.13.36.2/24)
#   --gateway-ip <ip/mask>      Gateway tunnel IPv4 address (default: 10.13.36.1/24)
#   --help, -h                  Display usage guide
# ==============================================================================

set -euo pipefail

# Default Parameters
ROLE=""
MODE="wg"
GAME_PORT=25565
WG_PORT=51820
AWG_PORT=51821

WG_GW_IPV4="10.13.36.1/24"
WG_GW_IPV6="fd00:36::1/64"
WG_NODE_IPV4="10.13.36.2/24"
WG_NODE_IPV6="fd00:36::2/64"

AWG_GW_IPV4="10.13.37.1/24"
AWG_GW_IPV6="fd00:37::1/64"
AWG_NODE_IPV4="10.13.37.2/24"
AWG_NODE_IPV6="fd00:37::2/64"

ENDPOINT=""
SERVER_KEY=""
CLIENT_KEY=""
KEEP_ALIVE=25

# ANSI Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Parse Command-Line Arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --role)
            ROLE="$2"
            shift 2
            ;;
        --mode)
            MODE="$2"
            shift 2
            ;;
        --game-port)
            GAME_PORT="$2"
            shift 2
            ;;
        --endpoint)
            ENDPOINT="$2"
            shift 2
            ;;
        --server-key)
            SERVER_KEY="$2"
            shift 2
            ;;
        --client-key)
            CLIENT_KEY="$2"
            shift 2
            ;;
        --client-ip)
            WG_NODE_IPV4="$2"
            shift 2
            ;;
        --gateway-ip)
            WG_GW_IPV4="$2"
            shift 2
            ;;
        --help|-h)
            sed -ne '/^#/!q;s/^# //p;s/^#$//p' "$0"
            exit 0
            ;;
        *)
            log_err "Unknown argument: $1"
            exit 1
            ;;
    esac
done

if [[ "$(id -u)" -ne 0 ]]; then
    log_err "Dyatel installer requires administrative privileges. Execute with sudo."
    exit 1
fi

if [[ -z "${ROLE}" ]]; then
    log_err "Missing mandatory option: --role <gateway|node>"
    exit 1
fi

# Detect package manager and install dependencies
log_info "Verifying system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq wireguard-tools ufw iproute2 iptables openresolv curl procps

# Setup Gateway Role
install_gateway() {
    log_info "Configuring Dyatel Ingress Gateway (Mode: ${MODE})..."

    # 1. Enable kernel forwarding
    log_info "Enabling kernel IPv4 and IPv6 forwarding..."
    cat > /etc/sysctl.d/99-dyatel-forward.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
EOF
    sysctl -p /etc/sysctl.d/99-dyatel-forward.conf >/dev/null

    IFACE="wg-dyatel"
    PORT="${WG_PORT}"
    CONF_DIR="/etc/wireguard"
    GW_ADDR="${WG_GW_IPV4}, ${WG_GW_IPV6}"
    CLIENT_ROUTE_IP="${WG_NODE_IPV4%%/*}"

    if [[ "${MODE}" == "awg" ]]; then
        IFACE="awg-dyatel"
        PORT="${AWG_PORT}"
        CONF_DIR="/etc/amnezia/amneziawg"
        GW_ADDR="${AWG_GW_IPV4}, ${AWG_GW_IPV6}"
        CLIENT_ROUTE_IP="${AWG_NODE_IPV4%%/*}"
        mkdir -p "${CONF_DIR}"
        chmod 700 "${CONF_DIR}"
    fi

    mkdir -p "${CONF_DIR}"
    chmod 700 "${CONF_DIR}"

    KEY_FILE="${CONF_DIR}/${IFACE}.key"
    if [[ ! -f "${KEY_FILE}" ]]; then
        wg genkey > "${KEY_FILE}"
        chmod 600 "${KEY_FILE}"
    fi
    GW_PRIV_KEY="$(cat "${KEY_FILE}")"
    GW_PUB_KEY="$(echo "${GW_PRIV_KEY}" | wg pubkey)"

    # Base Gateway Config
    cat > "${CONF_DIR}/${IFACE}.conf" <<EOF
[Interface]
Address = ${GW_ADDR}
ListenPort = ${PORT}
PrivateKey = ${GW_PRIV_KEY}
EOF
    chmod 600 "${CONF_DIR}/${IFACE}.conf"

    # Configure UFW and NAT rules
    log_info "Configuring firewall and port forwarding for game port ${GAME_PORT}..."
    ufw allow in to any port "${PORT}" proto udp comment "Dyatel Transport" || true
    ufw allow in to any port "${GAME_PORT}" proto tcp comment "Dyatel Game Ingress" || true

    # Insert NAT block into before.rules if absent
    if ! grep -q "DYATEL NAT BLOCK" /etc/ufw/before.rules; then
        sed -i "/^\*filter/i # BEGIN DYATEL NAT BLOCK\n*nat\n:PREROUTING ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n-A PREROUTING -p tcp --dport ${GAME_PORT} -j DNAT --to-destination ${CLIENT_ROUTE_IP}:${GAME_PORT}\n-A POSTROUTING -o ${IFACE} -d ${CLIENT_ROUTE_IP} -p tcp --dport ${GAME_PORT} -j MASQUERADE\nCOMMIT\n*mangle\n:FORWARD ACCEPT [0:0]\n-A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\nCOMMIT\n# END DYATEL NAT BLOCK\n" /etc/ufw/before.rules
    fi

    ufw reload || true

    SERVICE="wg-quick@${IFACE}"
    if [[ "${MODE}" == "awg" ]]; then
        SERVICE="awg-quick@${IFACE}"
    fi

    systemctl enable "${SERVICE}"
    systemctl restart "${SERVICE}"

    PUBLIC_IP="$(curl -s4 ifconfig.me || curl -s4 icanhazip.com || echo "YOUR_GATEWAY_IP")"

    cat <<EOF

================================================================================
${GREEN}🎉 DYATEL INGRESS GATEWAY INSTALLED SUCCESSFULLY!${NC}
================================================================================

Gateway Public Key: ${BOLD}${GW_PUB_KEY}${NC}
Gateway Endpoint:   ${BOLD}${PUBLIC_IP}:${PORT}${NC}
Game Ingress Port:  ${BOLD}${GAME_PORT}/tcp${NC}

To connect your game server node, execute this command on your home server:

  ${BLUE}curl -fsSL https://.../install.sh | sudo bash -s -- \\
      --role node --mode ${MODE} --endpoint ${PUBLIC_IP}:${PORT} --server-key "${GW_PUB_KEY}"${NC}

After your client runs, register their public key on this gateway:
  sudo wg set ${IFACE} peer <CLIENT_PUBLIC_KEY> allowed-ips ${CLIENT_ROUTE_IP}/32
================================================================================
EOF
}

# Setup Node Role
install_node() {
    log_info "Configuring Dyatel Client Node (Mode: ${MODE})..."

    if [[ -z "${ENDPOINT}" || -z "${SERVER_KEY}" ]]; then
        log_err "Node installation requires --endpoint <host:port> and --server-key <pubkey>"
        exit 1
    fi

    IFACE="wg-dyatel"
    CONF_DIR="/etc/wireguard"
    NODE_ADDR="${WG_NODE_IPV4}, ${WG_NODE_IPV6}"
    ALLOWED="10.13.36.0/24, fd00:36::/64"

    if [[ "${MODE}" == "awg" ]]; then
        IFACE="awg-dyatel"
        CONF_DIR="/etc/amnezia/amneziawg"
        NODE_ADDR="${AWG_NODE_IPV4}, ${AWG_NODE_IPV6}"
        ALLOWED="10.13.37.0/24, fd00:37::/64"
        mkdir -p "${CONF_DIR}"
        chmod 700 "${CONF_DIR}"
    fi

    mkdir -p "${CONF_DIR}"
    chmod 700 "${CONF_DIR}"

    KEY_FILE="${CONF_DIR}/${IFACE}.key"
    if [[ ! -f "${KEY_FILE}" ]]; then
        wg genkey > "${KEY_FILE}"
        chmod 600 "${KEY_FILE}"
    fi
    NODE_PRIV_KEY="$(cat "${KEY_FILE}")"
    NODE_PUB_KEY="$(echo "${NODE_PRIV_KEY}" | wg pubkey)"

    cat > "${CONF_DIR}/${IFACE}.conf" <<EOF
[Interface]
Address = ${NODE_ADDR}
PrivateKey = ${NODE_PRIV_KEY}

[Peer]
PublicKey = ${SERVER_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED}
PersistentKeepalive = ${KEEP_ALIVE}
EOF
    chmod 600 "${CONF_DIR}/${IFACE}.conf"

    # Restrict local game port strictly to tunnel interface
    log_info "Hardening local firewall..."
    ufw allow in on "${IFACE}" to any port "${GAME_PORT}" proto tcp comment "Game from Dyatel tunnel only" || true
    ufw allow 22/tcp comment "SSH access" || true
    ufw --force enable || true

    SERVICE="wg-quick@${IFACE}"
    if [[ "${MODE}" == "awg" ]]; then
        SERVICE="awg-quick@${IFACE}"
    fi

    systemctl enable "${SERVICE}"
    systemctl restart "${SERVICE}"

    cat <<EOF

================================================================================
${GREEN}🎉 DYATEL CLIENT NODE INSTALLED SUCCESSFULLY!${NC}
================================================================================

Client Public Key:  ${BOLD}${NODE_PUB_KEY}${NC}
Tunnel Interface:   ${BOLD}${IFACE}${NC}
Connected Gateway:  ${BOLD}${ENDPOINT}${NC}

Now inform your Gateway administrator to authorize your client key:
  ${YELLOW}${NODE_PUB_KEY}${NC}

Ensure your game server is listening on port ${GAME_PORT}:
  server-port=${GAME_PORT}
  server-ip=0.0.0.0
================================================================================
EOF
}

case "${ROLE}" in
    gateway)
        install_gateway
        ;;
    node)
        install_node
        ;;
    *)
        log_err "Invalid role '${ROLE}'. Supported roles: gateway, node"
        exit 1
        ;;
esac

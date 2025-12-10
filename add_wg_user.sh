#!/usr/bin/env bash
# Add a WireGuard peer with automatic IP allocation inside SUBNET (CIDR-aware).
# Works for /23, /24, and other IPv4 CIDRs.

WG_IFACE="${WG_IFACE:-wg0}"
WG_CONF="/etc/wireguard/${WG_IFACE}.conf"
SERVER_ADDR="${SERVER_ADDR:-192.168.2.1}"       # Server's WG address in the VPN
SUBNET="${SUBNET:-192.168.2.0/23}"              # VPN subnet (CIDR)
ENDPOINT="${ENDPOINT:-vpn.pricefx.net:51820}"   # Public endpoint clients connect to
DNS_SERVERS="${DNS_SERVERS:-1.1.1.1, 9.9.9.9}"  # Client DNS for full tunnel
CLIENTS_DIR="${CLIENTS_DIR:-/etc/wireguard/clients}"
DEFAULT_ALLOWEDIPS="${DEFAULT_ALLOWEDIPS:-0.0.0.0/0}" # Set to 192.168.2.0/23 for split tunnel by default
PRESHARED="${PRESHARED:-false}"                  # true to add a per-peer PresharedKey

# Require root
if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (sudo $0)" >&2
  exit 1
fi

# Basic checks
command -v wg >/dev/null || { echo "wg not found. Install wireguard-tools." >&2; exit 1; }
[[ -f "$WG_CONF" ]] || { echo "WireGuard config $WG_CONF not found." >&2; exit 1; }
umask 077
mkdir -p "$CLIENTS_DIR"

# Helpers for CIDR arithmetic (IPv4)
ip2int() {
  local IFS=.
  local a b c d
  read -r a b c d <<<"$1"
  printf '%u\n' $(( (a<<24) + (b<<16) + (c<<8) + d ))
}

int2ip() {
  printf '%d.%d.%d.%d\n' $(( ($1>>24)&255 )) $(( ($1>>16)&255 )) $(( ($1>>8)&255 )) $(( $1&255 ))
}

cidr_bounds() {
  local cidr_net="$1" net cidr
  IFS=/ read -r net cidr <<<"$cidr_net"
  local n; n=$(ip2int "$net")
  local mask=$(( 0xFFFFFFFF << (32-cidr) & 0xFFFFFFFF ))
  local netaddr=$(( n & mask ))
  local bcast=$(( netaddr | (~mask & 0xFFFFFFFF) ))
  echo "$netaddr $bcast"
}

# Validate SUBNET and SERVER_ADDR are coherent
if ! [[ "$SUBNET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]]; then
  echo "Invalid SUBNET format: $SUBNET (expected a.b.c.d/len)" >&2
  exit 1
fi
if ! [[ "$SERVER_ADDR" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "Invalid SERVER_ADDR format: $SERVER_ADDR (expected a.b.c.d)" >&2
  exit 1
fi

read NETADDR_INT BCAST_INT < <(cidr_bounds "$SUBNET")
SERVER_INT=$(ip2int "$SERVER_ADDR")

# Ensure server address is inside the usable range (not network or broadcast)
if (( SERVER_INT <= NETADDR_INT || SERVER_INT >= BCAST_INT )); then
  echo "SERVER_ADDR ($SERVER_ADDR) is not inside SUBNET ($SUBNET) usable range." >&2
  exit 1
fi

# Collect used /32s from running state and config, restricted to SUBNET
USED_IPS="$(
  {
    wg show "$WG_IFACE" 2>/dev/null | awk '/allowed ips:/ {print $3}';
    awk -F'= *' 'tolower($1) ~ /allowedips/ {print $2}' "$WG_CONF" 2>/dev/null;
  } \
  | tr -d ' ' | tr ',' '\n' \
  | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/32' \
  | cut -d/ -f1 \
  | while read -r ip; do
      ipi=$(ip2int "$ip")
      if (( ipi >= NETADDR_INT && ipi <= BCAST_INT )); then
        echo "$ip"
      fi
    done \
  | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n | uniq
)"

# Find next free IP inside SUBNET, skipping server and network/broadcast
NEXT_IP=""
for ((ipi=NETADDR_INT+1; ipi<=BCAST_INT-1; ipi++)); do
  cand="$(int2ip "$ipi")"
  [[ "$cand" == "$SERVER_ADDR" ]] && continue
  if ! grep -qx "$cand" <<<"$USED_IPS"; then
    NEXT_IP="$cand"
    break
  fi
done
[[ -n "$NEXT_IP" ]] || { echo "No free IPs left in ${SUBNET}." >&2; exit 1; }
echo "Next available VPN IP: ${NEXT_IP}/32"

# Prompt for client name
read -rp "Client name (no spaces, used for filenames/comments): " NAME
[[ -n "${NAME:-}" ]] || { echo "Name is required." >&2; exit 1; }

# Ask whether to generate keypair on server
read -rp "Generate client keypair on server and embed PrivateKey in QR? [y/N]: " GEN_KEYS
GEN_KEYS="${GEN_KEYS:-N}"

CLIENT_PRIV=""
CLIENT_PUB=""

is_b64_44() { [[ "$1" =~ ^[A-Za-z0-9+/]{43}=$ ]]; }

if [[ "$GEN_KEYS" =~ ^[Yy]$ ]]; then
  CLIENT_PRIV="$(wg genkey)"
  CLIENT_PUB="$(printf %s "$CLIENT_PRIV" | wg pubkey)"
  echo "Client keypair generated on server."
else
  read -rp "Client public key: " CLIENT_PUB
  [[ -n "$CLIENT_PUB" ]] || { echo "Public key is required." >&2; exit 1; }
  if ! is_b64_44 "$CLIENT_PUB"; then
    echo "Warning: Public key format is unusual (expected 44-char base64 ending with =). Proceeding anyway." >&2
  fi
fi

# Optional preshared key
PSK=""
if [[ "$PRESHARED" == "true" ]]; then
  PSK="$(wg genpsk)"
fi

# Safety: do not add duplicate peer
if wg show "$WG_IFACE" peers 2>/dev/null | grep -qx "$CLIENT_PUB"; then
  echo "Peer with this public key already exists on ${WG_IFACE}." >&2
  exit 1
fi

# Add peer live
WG_SET_ARGS=(set "$WG_IFACE" peer "$CLIENT_PUB" allowed-ips "${NEXT_IP}/32")
if [[ -n "$PSK" ]]; then
  WG_SET_ARGS+=(preshared-key /dev/fd/3)
  exec 3<<<"$PSK"
fi
wg "${WG_SET_ARGS[@]}"

# Persist to server config
{
  echo ""
  echo "[Peer]"
  echo "# ${NAME}"
  echo "PublicKey = ${CLIENT_PUB}"
  [[ -n "$PSK" ]] && echo "PresharedKey = ${PSK}"
  echo "AllowedIPs = ${NEXT_IP}/32"
} >> "$WG_CONF"

# Create client config
SERVER_PUB="$(wg show "$WG_IFACE" public-key)"
CLIENT_CONF="${CLIENTS_DIR}/${NAME}.conf"

{
  echo "# ${NAME} client config"
  echo ""
  echo "[Interface]"
  if [[ -n "$CLIENT_PRIV" ]]; then
    echo "PrivateKey = ${CLIENT_PRIV}"
  else
    echo "# PrivateKey not embedded. Insert your actual PrivateKey below:"
    echo "PrivateKey = REPLACE_WITH_YOUR_PRIVATE_KEY"
  fi
  echo "Address = ${NEXT_IP}/32"
  echo "DNS = ${DNS_SERVERS}"
  echo ""
  echo "[Peer]"
  echo "PublicKey = ${SERVER_PUB}"
  [[ -n "$PSK" ]] && echo "PresharedKey = ${PSK}"
  echo "AllowedIPs = ${DEFAULT_ALLOWEDIPS}"
  echo "Endpoint = ${ENDPOINT}"
  echo "PersistentKeepalive = 25"
} > "$CLIENT_CONF"
chmod 600 "$CLIENT_CONF"

echo "Peer added and persisted."
echo "Client config written to: ${CLIENT_CONF}"

# Show QR only if a real PrivateKey is present
if [[ -n "$CLIENT_PRIV" ]]; then
  if command -v qrencode >/dev/null; then
    echo ""
    echo "QR code (scan with WireGuard mobile):"
    qrencode -t ansiutf8 < "$CLIENT_CONF"
    qrencode -o "${CLIENT_CONF%.conf}.png" < "$CLIENT_CONF" 2>/dev/null || true
    echo "PNG saved to: ${CLIENT_CONF%.conf}.png"
  else
    echo "qrencode not found; install with: apt-get install -y qrencode"
  fi
else
  echo "Note: QR not shown because PrivateKey is missing in the config. Mobile import requires a valid PrivateKey."
  echo "      Either generate keys here next time, or create the tunnel on the device and paste this config manually."
fi

echo ""
echo "Summary:"
echo "* Name:           ${NAME}"
echo "* VPN IP:         ${NEXT_IP}/32"
echo "* Full/Split:     ${DEFAULT_ALLOWEDIPS}"
echo "* Endpoint:       ${ENDPOINT}"    
[[ -n "$PSK" ]] && echo "* PresharedKey:   enabled"
echo "* Verify:         wg show ${WG_IFACE}"

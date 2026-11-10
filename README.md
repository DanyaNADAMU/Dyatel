# Dyatel (Дятел) 🪵

[![Bitcoin Timestamped](https://img.shields.io/badge/OpenTimestamps-Anchored-blue.svg)](https://opentimestamps.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

> **High-Performance Multi-Transport Game Proxy & NAT Traversal Suite**  
> Drill through residential CGNAT walls and expose your self-hosted game servers to the world with enterprise DDoS masking and zero latency overhead.

---

## English | [Русский](README.ru.md)

---

## 🌟 Overview

Hosting dedicated game servers (such as **Minecraft**, Palworld, Rust, or Valheim) from a home workstation or homelab behind residential Internet Service Providers is challenging:
* **Carrier-Grade NAT (CGNAT)**: No public IPv4 address and blocked inbound ports.
* **Security & DDoS Risks**: Exposing home IP addresses risks ISP throttling, home network scanning, or local connection drops.
* **Censorship & DPI Filtering**: Standard UDP VPN handshakes are increasingly degraded or blocked by deep packet inspection (DPI) middleboxes.

**Dyatel** (*"The Woodpecker"*) solves this cleanly. It creates an isolated, bidirectional tunnel between your home server and a public VPS gateway, forwarding incoming players transparently into your local game instance with **zero client-side mods or VPN software required for players**.

```text
[ Players Everywhere ]
        │  (connect to: play.example.com:25565)
        ▼
┌────────────────────────────────────────────────────────┐
│               DYATEL INGRESS GATEWAY                   │
│   - Public Dual-Stack VPS (IPv4 + Routed IPv6)        │
│   - L4 DNAT / Direct IPv6 Forwarding                   │
│   - TCP MSS Clamping (PMTU aligned, zero fragmentation)│
│   - Strict Perimeter Isolation (Host ports protected)  │
└──────────────────────────┬─────────────────────────────┘
                           │
       =========================================
       Encrypted Tunnel (Selected Transport)
         • WireGuard: UDP 51820 (Maximum FPS/Low RTT)
         • AmneziaWG: UDP 51821 (Obfuscated DPI Evasion)
         • Xray gRPC: TCP 443   (Real TLS Masquerading)
       =========================================
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│               DYATEL CLIENT NODE                       │
│   - Self-Hosted Machine behind Residential NAT         │
│   - Single-Command Installation (amneziawg-go userspace│
│   - Local UFW Firewall (Game port accessible ONLY      │
│     via tunnel, isolated from home Wi-Fi & LAN)        │
│   - Game Server Listening on 127.0.0.1:25565           │
└────────────────────────────────────────────────────────┘
```

---

## 🚀 Quickstart in 60 Seconds

### Step 1: On Your Public Gateway (VPS)
Run the one-click installer to configure the ingress gateway:

```bash
curl -fsSL https://raw.githubusercontent.com/danyanadamu/Dyatel/main/scripts/install.sh | sudo bash -s -- --role gateway
```

The installer configures forwarding, sets up firewall rules, and outputs your **Gateway Public Key** and **Join Command**.

### Step 2: On Your Home Game Server
Run the installer in node mode with the gateway credentials:

```bash
curl -fsSL https://raw.githubusercontent.com/danyanadamu/Dyatel/main/scripts/install.sh | sudo bash -s -- \
    --role node \
    --endpoint "<GATEWAY_IP>:51820" \
    --server-key "<GATEWAY_PUBLIC_KEY>"
```

### Step 3: Start Playing!
Configure your Minecraft `server.properties`:
```properties
server-port=25565
server-ip=0.0.0.0
```
Share your gateway address (`play.example.com` or `GATEWAY_IP`) with players. They join directly through the standard game client!

---

## 🧩 Modularity & Pluggability

Dyatel is designed with strict modularity. Transports operate as pluggable modules that can run all-in-one or distributed across different servers:

| Transport Module | Default Port | Protocol | Best For |
| :--- | :--- | :--- | :--- |
| **WireGuard** | `51820/udp` | UDP | Maximum throughput, lowest possible tick latency. |
| **AmneziaWG** | `51821/udp` | Obfuscated UDP | Bypassing DPI / TSPU handshake blocking using junk packets (`Jc`) & magic headers (`H1-H4`). |
| **Xray Reverse** | `443/tcp` | gRPC over TLS 1.3 | Ultimate censorship evasion when UDP is severely throttled. Masquerades as valid HTTPS web traffic. |

---

## 🛠️ Ansible Deployment

For automated homelab and infrastructure-as-code orchestration, Dyatel provides production-grade Ansible roles:

```bash
cd ansible
cp inventory.example.ini inventory.ini
ansible-playbook playbooks/site.yml
```

### Feature Flags:
```yaml
dyatel_gateway_enable_wireguard: true
dyatel_gateway_enable_amneziawg: true
dyatel_gateway_game_port: 25565
```

---

## 🔒 Security & Privacy Guarantees

* **Zero Leakage**: Your home IP address is completely shielded behind the public VPS gateway.
* **Perimeter Defense**: The client node firewall allows incoming game traffic **strictly** from the encrypted tunnel interface, protecting your server against home network malware and port scanners.
* **Host Protection**: The gateway firewall unconditionally drops any connection attempt from the game tunnel to private infrastructure networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or management daemons (`22`, `80`, `443`).

---

## 📜 Cryptographic Proofs & Verification

Every commit and tag in Dyatel is cryptographically signed using SSH Ed25519 keys (`.allowed_signers`) and mathematically anchored into the Bitcoin blockchain via **OpenTimestamps**.

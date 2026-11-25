# Attaching Your Machine to Dyatel

This guide walks a **proxer** (the person who runs the server) and a
**client** (the person who consumes the tunnel) from zero to a working
public endpoint. Two paths exist for both sides: the **Tier-0 offline
path** (no daemon, no database, no account — just rendering and
`wg-quick`) and the **Tier-1 managed path** (the daemon tracks state,
opens firewall rules and re-applies drift).

Terminology (RFC §4): `проксер` = the host owner — the machine being
exposed; `клиент` = the consumer — the person dialing in.

---

## 1. Proxer: expose a server behind CGNAT

### 1.1 Generate the keypair locally (BYOK)

The private key never leaves your machine; only the public half is
submitted to the daemon (RFC §3.4b).

```bash
wg genkey | tee /etc/dyatel-private.key | wg pubkey
chmod 600 /etc/dyatel-private.key
cat /etc/dyatel-private.key.pub   # 44-char public key
```

For AmneziaWG use `awg genkey | tee ... | awg pubkey`.

### 1.2 Create the host

**Managed (panel).** Sign in at `https://dyatel.<domain>`, press **Add
host**, paste the public key, pick the consumer from the directory and
choose the transport.

**Managed (CLI).**

```bash
export DYATEL_TOKEN=dyatel_…        # from the panel: Tokens -> Mint token
export DYATEL_API=https://dyatel.<domain>

dyatelctl hosts create --name tiny-mc \
  --wg-pubkey "$(cat /etc/dyatel-private.key.pub)" \
  --transport wireguard \
  --consumer-id <consumer-uuid>     # `dyatelctl users list <name>`
```

**Tier 0 (no daemon at all).** Render both sides and the gateway
aggregate offline:

```bash
dyatelctl gen wireguard --help     # flags: --name, --endpoint, --forwards
```

### 1.3 Render the proxer config

```bash
dyatelctl hosts config proxer <host-id> --out /etc/wireguard/dyatel.conf
```

The daemon returns a config with a `{{PRIVATE_KEY}}` placeholder — it
never had your private key. Fill it in:

```bash
sed -i "s|{{PRIVATE_KEY}}|$(cat /etc/dyatel-private.key)|" /etc/wireguard/dyatel.conf
```

### 1.4 Bring the tunnel up

```bash
wg-quick up dyatel
systemctl enable wg-quick@dyatel     # optional: survive reboots
```

### 1.5 Open the proxer-side firewall (RFC §6 contract)

The gateway's UDP replies are source-routed from its **LAN** address,
not the public IP you dialed, so conntrack never matches the reverse
tuple and a default-deny UFW drops them as unsolicited:

```bash
ufw allow in proto udp from <gateway-public-ip> to any port <listen_port>
# when gateway and host share a LAN, add the LAN path too:
ufw allow in proto udp from <gateway-lan-cidr> to any port <listen_port>
```

### 1.6 Publish a service

**Owner publishes forwards** (RFC §4): the person who runs the machine
decides what is exposed.

```bash
dyatelctl forwards create <host-id> --public-port 25565 --target-port 25565 --proto tcp --label minecraft
```

Within one reconcile tick the gateway opens `25565/tcp` in UFW, DNATs it
to your tunnel IP and masquerades the reply path. Check the result:

```bash
dyatelctl status          # admin-only drift report
dyatelctl events          # your recent actions
```

Players now connect to `<gateway-ip>:25565`. DNS names for forwards are
not implemented yet — use `IP:port`.

---

## 2. Client: consume a tunnel

1. The proxer invites you as the host's consumer (panel: directory
   picker; CLI: `--consumer-id`). A host has exactly one consumer.
2. Generate your keypair locally and register the public half:

   ```bash
   wg genkey | tee /etc/dyatel-client.key | wg pubkey
   dyatelctl hosts register-consumer-key <host-id> --wg-pubkey "$(cat /etc/dyatel-client.key.pub)"
   ```

3. Fetch your config, fill in the key, bring it up:

   ```bash
   dyatelctl hosts config client <host-id> --out /etc/wireguard/dyatel-client.conf
   sed -i "s|{{PRIVATE_KEY}}|$(cat /etc/dyatel-client.key)|" /etc/wireguard/dyatel-client.conf
   wg-quick up dyatel-client
   ```

4. Verify the handshake and reach the proxer's tunnel IP:

   ```bash
   wg show dyatel-client latest-handshakes   # non-zero timestamp = healthy
   ping -c3 <proxer-tunnel-ip>
   ```

Your config's `AllowedIPs` is the proxer tunnel address only, so normal
internet traffic keeps using your own uplink — the tunnel is a private
path to that one machine.

---

## 3. Troubleshooting

| symptom | cause | fix |
|---|---|---|
| handshake OK, no echo reply | missing route, or proxer-side UFW dropped the reply | §1.5; check `ip route get <peer-tunnel-ip>` on the gateway |
| no handshake at all | wrong endpoint/port, or public port not open | `dyatelctl status`, then `ufw status` on the gateway |
| config says `{{PRIVATE_KEY}}` | placeholder never substituted | fill it from your local key file |
| `412: consumer key not registered` | client has not submitted a BYOK public key | §2 step 2 |
| forward created but nothing listens | reconciler has not ticked yet | `dyatelctl reconcile` |

---

## 4. Cheat sheet

```bash
dyatelctl me                                  # who am I, which auth
dyatelctl hosts list                          # my hosts (owner + consumer)
dyatelctl hosts edit <id> --keepalive 15      # mutable knobs only
dyatelctl tokens create --label laptop        # mint a PAT (shown once)
dyatelctl tokens list / rm <id>               # audit / revoke
dyatelctl users list dima                     # invitation directory
dyatelctl events --limit 20                   # audit trail
dyatelctl reconcile                           # force a loop pass
```
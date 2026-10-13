# univpn-cli

A minimal command-line client for Leagsoft/Huawei UniVPN SSL gateways (the
gateway host and port go in the config). No GUI, no setuid service — a single
Python file using only the standard library plus a TUN device.

It exists because the official client is a Qt GUI driving a setuid-root service
over an encrypted local socket; there is no documented CLI. The wire protocol
here was reverse-engineered by capturing the official client's TLS traffic.

## Why it works without the national-crypto (GM) stack

This gateway's profile has `igmalgorithmEnable = 0`: it speaks **standard TLS**
on port 12443, and the client does **not** verify the server certificate. So no
`libgmssl` / SM2 / SM3 / SM4 is needed — plain `ssl.CERT_NONE` connects.

## Protocol

All frames: `SESSION(c1 92 a4 d6) + VER(0x01) + CMD(1) + LEN(2 BE) + PAYLOAD`.

| CMD  | meaning | request payload | response |
|------|---------|-----------------|----------|
| 0x01 | auth    | gwname[256]+4 zero bytes, then TLV {1:user\0, 2:pass\0, 3:mac} | TLV {3: 32-byte SessionID} |
| 0x03 | config  | SessionID(32) | 4-byte header + TLV {1: VIP(+prefix), 4: blob with pushed DNS} |
| 0x64 | open    | SessionID(32) | ack `00` |
| 0x66 | data    | 8 zero bytes + raw IP packet | same (strip 8, write to TUN) |

Each step is a separate TLS connection to `:12443`; the 32-byte SessionID from
auth ties them together. The password rides in TLV tag 2 as near-plaintext over
TLS.

## Usage

```sh
cp univpn.conf.example univpn.conf      # then edit it
chmod 600 univpn.conf
sudo python3 univpn.py
```

`univpn.conf` (section `[vpn]`):

- `gateway`, `port`, `username`, `password` — login.
- `mac` — any `XXXX-XXXX-XXXX` string; the gateway logs it but does not check it.
- `routes` — comma-separated CIDRs sent over the tunnel:
  - empty  → interface comes up, **no routes added** (safe default).
  - `default` or `full` → full tunnel (all traffic via VPN). The client pins the
    gateway IP to your real uplink first so its own TLS link does not blackhole.
  - `10.1.0.0/16, 192.168.9.0/24` → split tunnel, only those nets via VPN.
- `dns` — override pushed DNS; empty uses what the gateway sends.

Stop with Ctrl+C; the TUN interface and its routes are removed on exit.

## Known limits (deliberate v1 shortcuts)

- **Keepalive is unverified.** The gateway kicks an idle control connection
  after ~30 s (per the openunivpn notes). This client pokes every 10 s; if the
  link still drops while idle, the auto-reconnect loop re-establishes it. If
  that churns, send real traffic through the tunnel or replace the poke in
  `keepalive()` with a periodic packet to an internal host.
- **Routes from the gateway are not auto-applied.** Config parsing extracts the
  VIP and pushed DNS; the pushed route list (TLV tag 4 blob) is not decoded, so
  you choose routes in `univpn.conf`. If the assigned VIP lands in a subnet that
  overlaps a local Docker/bridge network, prefer explicit split routes over
  `full` unless you know the overlap is fine.
- **Policy routing interaction.** If the host has policy routing rules (e.g.
  singbox/tailscale with separate routing tables), a plain `ip route … dev
  univpn0` in the main table may be overridden for some destinations. Adjust
  policy rules if needed.
- **No server cert check** — matches the official client, but it means no MITM
  protection. Fine on a trusted path; do not use over hostile networks.

## Credit

TUN setup, forwarding loop, keepalive/reconnect structure follow the
[openunivpn](https://github.com/tsaitang404/openunivpn) project (MIT). The auth
and `0x66` data framing are specific to this gateway and come from the capture,
not from openunivpn (which uses an HTTP `/netextension` login and a different
frame layout).

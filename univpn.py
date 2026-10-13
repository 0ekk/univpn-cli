#!/usr/bin/env python3
"""Minimal command-line client for a Leagsoft/Huawei UniVPN SSL gateway.

Protocol reverse-engineered by capturing the official UniVPNCS client's TLS
traffic (standard TLS on :12443, no GM, server cert not verified by the client).
TUN/forwarding scaffolding follows the openunivpn project (MIT); the wire
protocol core (binary CADM auth + 0x66 data framing) is specific to this
gateway and was taken from the capture, not from openunivpn (which uses an
HTTP /netextension login and a different frame layout).

Frame = SESSION(4) + VER(0x01) + CMD(1) + LEN(2 BE) + PAYLOAD.
  CMD 0x01 auth : gwname[256] + TLV{1:user, 2:pass, 3:mac}  -> TLV{3: 32B SID}
  CMD 0x03 cfg  : SID(32)                                   -> hdr + TLV{1: VIP, 4: blob(DNS/routes)}
  CMD 0x64 open : SID(32)                                   -> ack 00
  CMD 0x66 data : zero(8) + raw IP packet                   <-> same

Run as root (needs TUN). Reads ./univpn.conf (see univpn.conf.example).
"""
import configparser, fcntl, ipaddress, os, select, signal, socket, ssl, struct, subprocess, sys, threading, time

SESSION = bytes.fromhex("c192a4d6")
VER = 0x01
CMD_AUTH, CMD_CFG, CMD_OPEN, CMD_DATA = 0x01, 0x03, 0x64, 0x66

TUNSETIFF = 0x400454CA
IFF_TUN, IFF_NO_PI = 0x0001, 0x1000

KEEPALIVE_IDLE = 10   # seconds; gateway kicks idle control conn (~34s observed by openunivpn)
STALE_TIMEOUT = 40    # no data-frame rx for this long -> reconnect
RECONNECT_DELAY = 3


def log(*a):
    print(f"[{time.strftime('%H:%M:%S')}]", *a, flush=True)


def load_conf():
    cp = configparser.ConfigParser()
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "univpn.conf")
    if not cp.read(path):
        sys.exit(f"config not found: {path} (copy univpn.conf.example)")
    g = cp["vpn"]
    return {
        "host": g.get("gateway"),
        "port": g.getint("port", 12443),
        "user": g.get("username"),
        "password": g.get("password"),
        "mac": g.get("mac", "0123-4567-89AB"),
        "tun": g.get("tun", "univpn0"),
        "mtu": g.getint("mtu", 1300),
        "routes": [r.strip() for r in g.get("routes", "default").split(",") if r.strip()],
        "dns": [d.strip() for d in g.get("dns", "").split(",") if d.strip()],
    }


# ---- framing -------------------------------------------------------------

def frame(cmd, payload=b""):
    return SESSION + bytes([VER, cmd]) + struct.pack(">H", len(payload)) + payload


def recv_frame(sock):
    """Read one full frame; return (cmd, payload) or (None, None) on EOF."""
    hdr = recv_exact(sock, 8)
    if hdr is None or hdr[:4] != SESSION:
        return None, None
    cmd = hdr[5]
    ln = struct.unpack(">H", hdr[6:8])[0]
    payload = recv_exact(sock, ln) if ln else b""
    if payload is None:
        return None, None
    return cmd, payload


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        try:
            d = sock.recv(n - len(buf))
        except (socket.timeout, ssl.SSLWantReadError):
            raise
        if not d:
            return None
        buf += d
    return buf


def tls_connect(host, ip, port):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE   # official client does not verify the gateway cert
    raw = socket.create_connection((ip, port), timeout=15)
    return ctx.wrap_socket(raw, server_hostname=host)


def parse_tlvs(blob, start=0):
    out, i = [], start
    while i + 4 <= len(blob):
        tag = struct.unpack(">H", blob[i:i + 2])[0]
        ln = struct.unpack(">H", blob[i + 2:i + 4])[0]
        if i + 4 + ln > len(blob):
            break
        out.append((tag, blob[i + 4:i + 4 + ln]))
        i += 4 + ln
    return out


def ip4(b):
    return ".".join(str(x) for x in b[:4])


# ---- protocol steps ------------------------------------------------------

def do_auth(host, ip, port, user, password, mac):
    """CMD 0x01: returns the 32-byte SessionID."""
    gwname = host.encode().ljust(256, b"\x00") + b"\x00\x00\x00\x00"  # 256 name + 4 reserved
    tlv = (struct.pack(">HH", 0x0001, len(user) + 1) + user.encode() + b"\x00" +
           struct.pack(">HH", 0x0002, len(password) + 1) + password.encode() + b"\x00" +
           struct.pack(">HH", 0x0003, len(mac)) + mac.encode())
    s = tls_connect(host, ip, port)
    s.sendall(frame(CMD_AUTH, gwname + tlv))
    s.settimeout(10)
    cmd, body = recv_frame(s)
    s.close()
    if cmd != CMD_AUTH or body is None:
        raise RuntimeError(f"auth failed (cmd={cmd})")
    sid = None
    for tag, val in parse_tlvs(body):
        if tag == 0x0003 and len(val) == 32:
            sid = val
    if not sid:
        raise RuntimeError("auth: no SessionID in response "
                           "(wrong username/password, or account restricted)")
    return sid


def do_config(host, ip, port, sid):
    """CMD 0x03: returns dict(vip, prefix, dns[], routes[])."""
    s = tls_connect(host, ip, port)
    s.sendall(frame(CMD_CFG, sid))
    s.settimeout(10)
    cmd, body = recv_frame(s)
    s.close()
    if cmd != CMD_CFG or not body:
        raise RuntimeError(f"config failed (cmd={cmd})")
    cfg = {"vip": None, "prefix": 32, "dns": [], "routes": []}
    # body = 4-byte header (00 5a 00 00) + TLVs
    for tag, val in parse_tlvs(body, start=4):
        if tag == 0x0001 and len(val) >= 4:
            cfg["vip"] = ip4(val)
            if len(val) >= 5 and 0 < val[4] <= 32:
                cfg["prefix"] = val[4]
        elif tag == 0x0004:
            # blob holds pushed DNS and (possibly) split routes; scan for IPs.
            for off in range(0, len(val) - 3):
                quad = val[off:off + 4]
                if quad[0] in (223, 114, 8, 1, 10, 172, 192) and quad != b"\x00\x00\x00\x00":
                    ipc = ip4(quad)
                    if ipc not in cfg["dns"] and ipc.endswith((".5.5.5", ".114.114")):
                        cfg["dns"].append(ipc)
    return cfg


# ---- tun / routes / dns --------------------------------------------------

def create_tun(name):
    fd = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI))
    return fd


def sh(*args):
    subprocess.run(args, check=False, capture_output=True)


def orig_default():
    """(gateway_ip, dev) of the current default route, for pinning in full tunnel."""
    out = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True).stdout.split()
    gw = dev = None
    if "via" in out:
        gw = out[out.index("via") + 1]
    if "dev" in out:
        dev = out[out.index("dev") + 1]
    return gw, dev


def setup_iface(name, vip, prefix, mtu, routes, gw_ip):
    sh("ip", "link", "set", name, "up")
    sh("ip", "link", "set", name, "mtu", str(mtu))
    sh("ip", "addr", "add", f"{vip}/{prefix}", "dev", name)
    for r in routes:
        if r in ("default", "full"):
            # pin the VPN gateway's own IP to the real uplink first, or the
            # VPN's TLS connection gets routed into the tunnel and blackholes.
            o_gw, o_dev = orig_default()
            if o_gw and o_dev:
                sh("ip", "route", "add", f"{gw_ip}/32", "via", o_gw, "dev", o_dev)
            # full tunnel via two /1 routes so we don't clobber the system default
            sh("ip", "route", "add", "0.0.0.0/1", "dev", name)
            sh("ip", "route", "add", "128.0.0.0/1", "dev", name)
        else:
            sh("ip", "route", "add", r, "dev", name)


def teardown_iface(name):
    sh("ip", "link", "del", name)


# ---- main loop -----------------------------------------------------------

def run():
    if os.geteuid() != 0:
        sys.exit("must run as root (TUN)")
    c = load_conf()
    ip = socket.getaddrinfo(c["host"], None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    log(f"gateway {c['host']} -> {ip}:{c['port']}")

    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())

    while not stop.is_set():
        try:
            sid = do_auth(c["host"], ip, c["port"], c["user"], c["password"], c["mac"])
            log(f"authenticated, SID={sid[:6].hex()}...")
            cfg = do_config(c["host"], ip, c["port"], sid)
            if not cfg["vip"]:
                raise RuntimeError("no VIP returned by gateway")
            dns = c["dns"] or cfg["dns"]
            log(f"VIP={cfg['vip']}/{cfg['prefix']} DNS={dns}")

            data = tls_connect(c["host"], ip, c["port"])
            data.sendall(frame(CMD_OPEN, sid))
            data.settimeout(10)
            cmd, _ = recv_frame(data)
            if cmd != CMD_OPEN:
                raise RuntimeError(f"tunnel open refused (cmd={cmd})")
            log("data tunnel open")

            tun = create_tun(c["tun"])
            routes = c["routes"]  # empty = interface up, no routes (safe); never auto full-tunnel
            setup_iface(c["tun"], cfg["vip"], cfg["prefix"], c["mtu"], routes, ip)
            log(f"{c['tun']} up (routes: {'/'.join(routes) or 'none'}); Ctrl+C to stop")

            forward(data, tun, stop)
        except Exception as e:
            log(f"error: {e}")
        finally:
            try:
                teardown_iface(c["tun"])
            except Exception:
                pass
        if stop.is_set():
            break
        log(f"reconnecting in {RECONNECT_DELAY}s...")
        time.sleep(RECONNECT_DELAY)


def forward(data, tun, stop):
    last_rx = [time.time()]
    lock = threading.Lock()
    dead = threading.Event()

    def tun_to_tls():
        while not stop.is_set() and not dead.is_set():
            r, _, _ = select.select([tun], [], [], 1)
            if not r:
                continue
            try:
                pkt = os.read(tun, 65535)
            except OSError:
                dead.set(); return
            if pkt:
                with lock:
                    try:
                        data.sendall(frame(CMD_DATA, b"\x00" * 8 + pkt))
                    except Exception:
                        dead.set(); return

    def tls_to_tun():
        data.settimeout(5)
        while not stop.is_set() and not dead.is_set():
            try:
                cmd, payload = recv_frame(data)
            except socket.timeout:
                if time.time() - last_rx[0] > STALE_TIMEOUT:
                    log("stale (no data), reconnecting"); dead.set(); return
                continue
            except Exception:
                dead.set(); return
            if cmd is None:
                dead.set(); return
            if cmd == CMD_DATA and len(payload) > 8:
                last_rx[0] = time.time()
                os.write(tun, payload[8:])

    def keepalive():
        while not stop.is_set() and not dead.is_set():
            time.sleep(KEEPALIVE_IDLE)
            with lock:
                try:
                    data.sendall(frame(CMD_OPEN, b"\x00" * 8))  # ponytail: benign poke; swap if gateway ignores it
                except Exception:
                    dead.set(); return

    ts = [threading.Thread(target=f, daemon=True) for f in (tun_to_tls, tls_to_tun, keepalive)]
    for t in ts:
        t.start()
    while not stop.is_set() and not dead.is_set():
        time.sleep(0.3)
    dead.set()
    try:
        data.close()
    except Exception:
        pass


if __name__ == "__main__":
    run()

#!/usr/bin/env python3
"""netglass server: serves the dashboard and samples your network on a fixed interval.

Usage: python3 server.py [path-to-config.json]   (default: config.json, fallback config.example.json)
Listens on 127.0.0.1:PORT from the config; expose remotely via Tailscale Serve, an SSH tunnel or a reverse proxy.

Files created next to the config: status.json, history.jsonl, state.json, notes.json, assignments.json.
"""
import ipaddress, json, os, re, shutil, socket, subprocess, sys, threading, time, traceback
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "config.json")
if not os.path.exists(CONFIG_PATH):
    CONFIG_PATH = os.path.join(HERE, "config.example.json")
with open(CONFIG_PATH, encoding="utf-8") as _fh:
    CFG = json.load(_fh)

PORT = int(CFG.get("port", 8790))
INTERVAL_S = int(CFG.get("interval_s", 120))
SMOOTH_S = int(CFG.get("lan_presence_window_s", 600))
HISTORY_KEEP_S = int(CFG.get("history_days", 7)) * 86400
ALERT_AFTER_S = int(CFG.get("alert_after_s", 300))
STATE_DIR = os.path.dirname(os.path.abspath(CONFIG_PATH))
DATA = lambda name: os.path.join(STATE_DIR, name)  # noqa: E731

PING_TARGETS = dict(CFG.get("ping_targets", {"internet": "1.1.1.1"}))
TCP_SERVICES = [(s["id"], s["host"], int(s["port"])) for s in CFG.get("tcp_services", [])]
DEVICE_IDS = list(CFG.get("device_ids", []))
LAN_SMOOTH = set(CFG.get("smoothed_devices", []))
LABELS = dict(CFG.get("labels", {}))
KNOWN_MAC = dict(CFG.get("known_macs", {}))
WOL_BROADCASTS = list(CFG.get("wol_broadcast", []))
TS_IP = dict(CFG.get("tailscale_ips", {}))
TAILSCALE = CFG.get("tailscale_bin") or next((p for p in ("/opt/homebrew/bin/tailscale", "/usr/bin/tailscale", "/usr/local/bin/tailscale") if os.path.exists(p)), "tailscale")
VENDOR_FILE = CFG.get("oui_file") or next((p for p in ("/opt/homebrew/opt/nmap/share/nmap/nmap-mac-prefixes", "/usr/share/nmap/nmap-mac-prefixes") if os.path.exists(p)), None)
HA_REGISTRY = os.path.expanduser(CFG["ha_device_registry"]) if CFG.get("ha_device_registry") else None
MOONRAKER = CFG.get("moonraker")  # "host:port" or null
ROCE_SSH_HOST = CFG.get("roce_ssh_host")  # probe RoCE links from this ssh host, or null
LAN_CIDRS = [ipaddress.ip_network(c) for c in CFG.get("lan_cidrs", ["192.168.1.0/24"])]
HINTS = [("somfy", "maybe a somfy hub"), ("overkiz", "maybe an Overkiz hub"), ("xiaomi", "Xiaomi device"),
         ("espressif", "ESP-based IoT device"), ("apple", "Apple device"), ("samsung", "Samsung device")]
NOTE_KEYS = {"name", "note", "conn"}
lock = threading.Lock()
VENDORS, _ha_cache = {}, {"mtime": None, "data": {}}

def load(name, default):
    try:
        with open(DATA(name), encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default

def save(name, data):
    tmp = DATA(name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=1)
    os.replace(tmp, DATA(name))

def load_vendors():
    if not VENDOR_FILE:
        return
    try:
        with open(VENDOR_FILE, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if len(line) > 7 and line[6] == " ":
                    VENDORS[line[:6].upper()] = line[7:].strip()
    except OSError:
        pass

def vendor_of(mac):
    try:
        if int(mac[:2], 16) & 2:
            return None  # locally administered
    except ValueError:
        return None
    return VENDORS.get(mac.replace(":", "")[:6].upper())

def ha_names():
    if not HA_REGISTRY:
        return {}
    try:
        mtime = os.path.getmtime(HA_REGISTRY)
        if mtime != _ha_cache["mtime"]:
            data = {}
            with open(HA_REGISTRY, encoding="utf-8") as fh:
                for d in json.load(fh)["data"]["devices"]:
                    for kind, val in d.get("connections", []):
                        if kind == "mac" and len(val) == 17:
                            data[val.lower()] = " ".join(x for x in (d.get("manufacturer"), d.get("name_by_user") or d.get("name")) if x)
            _ha_cache.update(mtime=mtime, data=data)
    except Exception:
        pass
    return _ha_cache["data"]

def _ping_cmd(ip, wait_ms):
    if sys.platform == "win32":
        return ["ping", "-n", "1", "-w", str(max(100, wait_ms)), ip]
    if sys.platform == "darwin":
        return ["ping", "-c1", "-W", str(wait_ms), ip]
    return ["ping", "-c1", "-W", str(max(1, round(wait_ms / 1000))), ip]  # linux: -W is seconds


def _parse_ping(out):
    m = re.search(r"=([\d.]+)\s*/?\s?ms", out) or re.search(r"time=([\d.]+)", out)
    if m:
        return float(m.group(1))
    if re.search(r"<1ms|<1 ms", out):
        return 0.4
    return None


def ping(ip, wait_ms=700):
    try:
        r = subprocess.run(_ping_cmd(ip, wait_ms), capture_output=True, text=True,
                           timeout=max(4, wait_ms / 1000 + 3))
    except Exception:
        return None
    if r.returncode != 0:
        return None
    return _parse_ping(r.stdout)


def _arp_cmd():
    if sys.platform == "win32":
        return ["arp", "-a"]
    if sys.platform == "darwin":
        return ["arp", "-an"]
    if shutil.which("ip"):
        return ["ip", "neigh"]
    return ["arp", "-an"]


def _parse_arp(out):
    """Return {ip: zero-padded mac} from linux `ip neigh`, linux/mac `arp` or windows `arp -a` output."""
    res = {}
    for line in out.splitlines():
        # windows: 192.168.1.10   aa-bb-cc-dd-ee-ff   dynamic
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F-]{17})\s", line)
        # linux ip neigh: 192.168.1.10 dev eth0 lladdr aa:... REACHABLE
        if not m:
            m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}).*?lladdr\s+([0-9a-f:]{11,17})", line)
        # linux/mac arp: ? (192.168.1.10) at aa:... on eth0 / 192.168.1.10 ether aa:... eth0
        if not m:
            m = re.search(r"\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([0-9a-f:]{11,17})", line) or \
                re.search(r"(\d{1,3}(?:\.\d{1,3}){3})\s+ether\s+([0-9a-f:]{11,17})", line)
        if m:
            mac = m.group(2).replace("-", ":").lower()
            res[m.group(1)] = ":".join(part.zfill(2) for part in mac.split(":"))
    return res


def arp_table():
    try:
        out = subprocess.run(_arp_cmd(), capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return {}
    raw = _parse_arp(out)
    return {ip: mac for ip, mac in raw.items() if any(ipaddress.ip_address(ip) in c for c in LAN_CIDRS)}

def tcp(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def ts_ping(ip):
    try:
        out = subprocess.run([TAILSCALE, "ping", "-c", "1", "--until-direct=false", "--timeout", "4s", ip],
                             capture_output=True, text=True, timeout=9).stdout
    except Exception:
        return None
    m = re.search(r"via (\S+) in ([\d.]+)(ms|s)\b", out)
    if not m:
        return None
    return {"rtt": float(m.group(2)) * (1000 if m.group(3) == "s" else 1),
            "relay": m.group(1).startswith("DERP("), "region": m.group(1)[5:-1] if m.group(1).startswith("DERP(") else None}

def ts_peers():
    try:
        ts = json.loads(subprocess.run([TAILSCALE, "status", "--json"], capture_output=True, text=True, timeout=10).stdout)
    except Exception:
        return {}
    return {dev: bool(p.get("Online")) for p in ts.get("Peer", {}).values() for ip, dev in TS_IP.items() if ip in p.get("TailscaleIPs", [])}

def roce_rtt():
    if not ROCE_SSH_HOST:
        return [None, None]
    cmd = "ping -c1 -W1 10.200.0.2 | grep -o 'time=[0-9.]*'; echo ---; ping -c1 -W1 10.200.1.2 | grep -o 'time=[0-9.]*'"
    try:
        out = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=4", ROCE_SSH_HOST, cmd],
                             capture_output=True, text=True, timeout=12).stdout
    except Exception:
        return [None, None]
    res = [float(m.group(1)) if (m := re.search(r"time=([\d.]+)", part)) else None for part in out.split("---")[:2]]
    return (res + [None, None])[:2]

def moonraker():
    if not MOONRAKER:
        return None
    try:
        out = subprocess.run(["curl", "-s", "-m", "5", "http://%s/printer/objects/query?print_stats&display_status&extruder&heater_bed&virtual_sdcard" % MOONRAKER],
                             capture_output=True, text=True, timeout=8).stdout
        st = json.loads(out)["result"]["status"]
        ps, ex, bed = st.get("print_stats", {}), st.get("extruder", {}), st.get("heater_bed", {})
        prog = (st.get("virtual_sdcard") or {}).get("progress") or (st.get("display_status") or {}).get("progress") or 0
        elapsed = ps.get("print_duration") or 0
        return {"state": ps.get("state"), "file": ps.get("filename") or None, "progress": round(float(prog), 4),
                "elapsed": int(elapsed), "eta": int(elapsed / prog - elapsed) if ps.get("state") == "printing" and prog > .01 else None,
                "message": ps.get("message") or None,
                "ext": [round(ex.get("temperature", 0), 1), round(ex.get("target", 0), 1)],
                "bed": [round(bed.get("temperature", 0), 1), round(bed.get("target", 0), 1)]}
    except Exception:
        return None

def norm_mac(mac):
    return ":".join(p.zfill(2) for p in mac.lower().split(":"))

def lan_hosts():
    hosts = []
    for net in LAN_CIDRS:
        hosts += [str(h) for h in net.hosts()]
    return hosts

def mdns_name(ip):
    """Best effort reverse name. None when nothing resolves quickly."""
    try:
        if sys.platform == "darwin":
            out = subprocess.run(["dscacheutil", "-q", "host", "-a", "ip", ip], capture_output=True, text=True, timeout=4).stdout
            m = re.search(r"hname:\s*(\S+)", out)
            if m:
                return m.group(1)
        elif sys.platform != "win32" and shutil.which("avahi-resolve"):
            out = subprocess.run(["avahi-resolve", "-a", ip], capture_output=True, text=True, timeout=4).stdout
            m = re.search(r"\S+\s+(\S+)", out)
            if m and "failed" not in out.lower():
                return m.group(1)
        return socket.getfqdn(ip) if socket.gethostbyaddr(ip)[0] else None
    except Exception:
        return None

# ---------- history ----------
def append_history(now, raw):
    with open(DATA("history.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"t": now, "d": raw}, separators=(",", ":")) + "\n")
    try:
        if os.path.getsize(DATA("history.jsonl")) > 3_000_000:
            rows = [r for r in read_history() if r["t"] >= now - HISTORY_KEEP_S]
            with open(DATA("history.jsonl.tmp"), "w", encoding="utf-8") as fh:
                for r in rows:
                    fh.write(json.dumps(r, separators=(",", ":")) + "\n")
            os.replace(DATA("history.jsonl.tmp"), DATA("history.jsonl"))
    except OSError:
        pass

def read_history():
    rows = []
    try:
        with open(DATA("history.jsonl"), encoding="utf-8") as fh:
            for line in fh:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    pass
    except FileNotFoundError:
        pass
    return rows

def summarize(now=None):
    now = now or time.time()
    rows = [r for r in read_history() if r["t"] >= now - HISTORY_KEEP_S]
    ids = set()
    for r in rows:
        ids.update(r["d"])
    items = {}
    for i in ids:
        s = [(r["t"], r["d"][i]) for r in rows if i in r["d"]]
        if not s:
            continue
        s24 = [x for x in s if x[0] >= now - 86400]
        bars = []
        for k in range(48):
            lo = now - 86400 + k * 1800
            b = [v for t, v in s24 if lo <= t < lo + 1800]
            bars.append(round(sum(b) / len(b), 2) if b else None)
        outs, cur, prev = [], None, None
        for t, v in s:
            if prev is not None and t - prev > 3 * INTERVAL_S and cur:
                if cur["n"] >= 2:
                    outs.append([cur["start"], prev])
                cur = None
            if v == 0:
                cur = cur or {"start": t, "n": 0}
                cur["n"] += 1
            elif cur:
                if cur["n"] >= 2:
                    outs.append([cur["start"], t])
                cur = None
            prev = t
        if cur and cur["n"] >= 2:
            outs.append([cur["start"], None])
        items[i] = {"u24": round(sum(v for _, v in s24) / len(s24) * 100, 1) if s24 else None,
                    "u7": round(sum(v for _, v in s) / len(s) * 100, 1), "bars": bars, "out": outs[-6:]}
    return {"ts": int(now), "since": rows[0]["t"] if rows else None, "items": items}

_hist_cache = {"t": 0.0, "v": None}

def history_cached():
    if time.time() - _hist_cache["t"] > 30 or _hist_cache["v"] is None:
        _hist_cache.update(t=time.time(), v=summarize())
    return _hist_cache["v"]

def state_at(hours):
    target = time.time() - max(0.25, hours) * 3600
    best = None
    for r in read_history():
        if r["t"] <= target + 60:
            best = r
        elif best and r["t"] - target > 3 * INTERVAL_S:
            break
    return best

# ---------- alerting ----------
def _desktop_notify(msg):
    try:
        if sys.platform == "darwin":
            subprocess.run(["osascript", "-e",
                            'display notification "%s" with title "netglass" sound name "Ping"' % msg],
                           timeout=10, check=False)
        elif sys.platform == "win32":
            scr = ("Add-Type -AssemblyName System.Windows.Forms;"
                   "Add-Type -AssemblyName System.Drawing;"
                   "$n=New-Object System.Windows.Forms.NotifyIcon;"
                   "$n.Icon=[System.Drawing.SystemIcons]::Warning;$n.Visible=$true;"
                   "$n.ShowBalloonTip(5000,'netglass','%s','Warning');Start-Sleep 6;$n.Dispose()" % msg.replace("'", "''"))
            subprocess.run(["powershell", "-NoProfile", "-Command", scr], timeout=15, check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            if shutil.which("notify-send"):
                subprocess.run(["notify-send", "netglass", msg], timeout=10, check=False)
    except Exception:
        pass


def alert(msg):
    print("alert:", msg, flush=True)
    al = CFG.get("alerting", {})
    if al.get("desktop_notifications", al.get("macos_notifications", True)):
        threading.Thread(target=_desktop_notify, args=(msg,), daemon=True).start()
    cfg = CFG.get("alerting", {})
    def push():
        try:
            if cfg.get("webhook"):
                subprocess.run(["curl", "-s", "-m", "6", "-X", "POST", "-H", "Content-Type: application/json",
                                "-d", json.dumps({"msg": msg}), cfg["webhook"]], stdout=subprocess.DEVNULL, timeout=8)
            if cfg.get("telegram_token") and cfg.get("telegram_chat"):
                subprocess.run(["curl", "-s", "-m", "6", "https://api.telegram.org/bot%s/sendMessage" % cfg["telegram_token"],
                                "-d", "chat_id=%s" % cfg["telegram_chat"], "-d", "text=netglass: %s" % msg],
                               stdout=subprocess.DEVNULL, timeout=8)
        except Exception:
            pass
    threading.Thread(target=push, daemon=True).start()

def label_of(key):
    return LABELS.get(key, key)

def send_wol(mac):
    pkt = bytes.fromhex(mac.replace(":", "")) * 16
    ok = False
    for addr in WOL_BROADCASTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(pkt, (addr, 9))
            s.close()
            ok = True
        except OSError:
            pass
    return ok

# ---------- collector ----------
def collect():
    now = int(time.time())
    state = load("state.json", {})
    seen, first, down = state.setdefault("seen", {}), state.setdefault("first", {}), state.setdefault("down", {})
    notified = state.setdefault("notified", {})
    mac_map = dict(KNOWN_MAC)
    mac_map.update(load("assignments.json", {}))
    id_mac = {}
    for m, i in mac_map.items():
        id_mac.setdefault(i, m)
    if not VENDORS:
        load_vendors()
    lan_ips = lan_hosts()
    with ThreadPoolExecutor(max_workers=64) as pool:
        lan_rtt = dict(zip(lan_ips, pool.map(ping, lan_ips)))
        extra_rtt = dict(zip(PING_TARGETS, pool.map(ping, PING_TARGETS.values())))
        arp = arp_table()
        retry = [ip for ip, mac in arp.items() if lan_rtt.get(ip) is None and mac_map.get(mac)]
        lan_rtt.update(zip(retry, pool.map(lambda ip: ping(ip, 1500), retry)))
    check = lambda s: tcp(s[1], s[2]) or tcp(s[1], s[2], 6)  # noqa: E731
    with ThreadPoolExecutor(max_workers=16) as pool:
        f_svc = {s[0]: pool.submit(check, s) for s in TCP_SERVICES}
        f_ts = {dev: pool.submit(ts_ping, ip) for ip, dev in TS_IP.items()}
        f_peers, f_roce, f_prn = pool.submit(ts_peers), pool.submit(roce_rtt), pool.submit(moonraker)
        svc = {k: f.result() for k, f in f_svc.items()}
        tsp, peers, roce, printer = {k: f.result() for k, f in f_ts.items()}, f_peers.result(), f_roce.result(), f_prn.result()
    ha = ha_names()
    saved_vendor = state.setdefault("vendor", {})
    ips, rtts, vend, unknown = {}, {}, {}, []
    for ip, mac in sorted(arp.items(), key=lambda kv: [int(x) for x in kv[0].split(".")]):
        if lan_rtt.get(ip) is None:
            continue
        dev = mac_map.get(mac)
        if dev:
            seen[dev] = now
            ips.setdefault(dev, []).append(ip)
            rtts.setdefault(dev, []).append(lan_rtt[ip])
            vend.setdefault(dev, vendor_of(mac) or ha.get(mac))
            if vend[dev]:
                saved_vendor[dev] = vend[dev]
        else:
            first.setdefault(mac, now)
            is_new = state.get("booted") and now - first[mac] < 2 * INTERVAL_S
            v = vendor_of(mac)
            if is_new:
                alert("New device on the network: %s%s" % (ip, (" (%s)" % v) if v else ""))
            hint = next((h for k, h in HINTS if v and k in v.lower()), None)
            unknown.append({"ip": ip, "mac": mac, "first_seen": first[mac], "private": mac[1] in "26ae",
                            "vendor": v, "ha": ha.get(mac), "hint": hint, "name": mdns_name(ip)})
    for dev, r in extra_rtt.items():
        if r is not None:
            seen[dev] = now
    for dev in CFG.get("always_up", ["self"]):
        seen[dev] = now
    if printer is not None and CFG.get("printer_id"):
        seen[CFG["printer_id"]] = now
    for dev, online in peers.items():
        if online:
            seen[dev] = now

    best = lambda xs: min(xs) if xs else None  # noqa: E731
    rtt = {d: best(r) for d, r in rtts.items()}
    rtt.update({k: v for k, v in extra_rtt.items()})
    for dev, t in tsp.items():
        if t:
            rtt[dev] = t["rtt"]
    links = {}
    for rule in CFG.get("link_rtts", []):  # [{"key": "router|pc", "device": "router"}, ...]
        dev, v = rule.get("device"), rtt.get(rule.get("device"))
        if dev and v is not None:
            e = {"rtt": round(v, 1)}
            if dev in tsp and tsp[dev]:
                e["relay"], e["region"] = tsp[dev]["relay"], tsp[dev]["region"]
            if rule.get("note"):
                e["note"] = rule["note"]
            links[rule["key"]] = e
    raw = {i: (1 if seen.get(i) == now else 0) for i in DEVICE_IDS if i in seen}
    raw.update({k: 1 if v else 0 for k, v in svc.items()})
    for k, v in raw.items():
        if v:
            down.pop(k, None)
            if notified.pop(k, None):
                alert("%s: back up" % label_of(k))
        else:
            down.setdefault(k, now)
    for k, since in list(down.items()):
        if not notified.get(k) and now - since >= ALERT_AFTER_S:
            notified[k] = True
            alert("%s is not responding" % label_of(k))
    append_history(now, raw)

    def dev(i):
        last = seen.get(i)
        d = {"up": bool(last and now - last <= (SMOOTH_S if i in LAN_SMOOTH else 0)), "last_seen": last, "ips": ips.get(i)}
        if id_mac.get(i):
            d["mac"] = id_mac[i]
        if vend.get(i) or saved_vendor.get(i):
            d["vendor"] = vend.get(i) or saved_vendor[i]
        if rtt.get(i) is not None:
            d["rtt"] = round(rtt[i], 1)
        if tsp.get(i):
            d["relay"], d["region"] = tsp[i]["relay"], tsp[i]["region"]
        if last is None:
            d["never"] = True
        if i in down:
            d["down_since"] = down[i]
        return d

    services = {k: {"up": bool(v), **({"down_since": down[k]} if k in down else {})} for k, v in svc.items()}
    status = {"ts": now, "interval": INTERVAL_S, "devices": {i: dev(i) for i in DEVICE_IDS}, "services": services,
              "links": links, "printer": printer, "unknown": unknown}
    save("state.json", state)
    state["booted"] = True
    save("status.json", status)
    return status

def collector_loop():
    while True:
        t0 = time.time()
        try:
            with lock:
                collect()
        except Exception as exc:
            print("collect failed:", repr(exc), flush=True)
            traceback.print_exc()
        time.sleep(max(10, INTERVAL_S - (time.time() - t0)))

def refresh_now():
    try:
        with lock:
            collect()
    except Exception as exc:
        print("refresh failed:", repr(exc), flush=True)

# ---------- http ----------
SKELETON = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">'
            '<style>body{margin:0;font:14px system-ui}img{max-width:100%}[hidden]{display:none!important}</style></head><body>')
VENDOR_JS = {
    "https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js": "vendor/three.min.js",
    "https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js": "vendor/OrbitControls.js",
}
STATIC = {"/status.json": "application/json", "/notes.json": "application/json",
          "/vendor/three.min.js": "text/javascript", "/vendor/OrbitControls.js": "text/javascript",
          "/manifest.webmanifest": "application/manifest+json", "/sw.js": "text/javascript", "/icon.png": "image/png"}

def export_csv():
    import io
    st = load("status.json", {})
    hist = history_cached()
    buf = io.StringIO()
    buf.write("id,ip,mac,vendor,up,last_seen,rtt_ms,uptime_24h_pct\n")
    for i in sorted(set(list(st.get("devices", {})) + list(st.get("services", {})))):
        d = st.get("devices", {}).get(i) or st.get("services", {}).get(i) or {}
        ts = d.get("last_seen")
        buf.write(",".join('"%s"' % str(x).replace('"', '""') if x is not None else "" for x in
                           [i, ";".join(d.get("ips") or []), d.get("mac", ""), d.get("vendor", ""), d.get("up", ""),
                            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "", d.get("rtt", ""),
                            (hist.get("items", {}).get(i) or {}).get("u24")]) + "\n")
    return buf.getvalue().encode("utf-8")

def stream_events(handler):
    handler.send_response(200)
    handler.send_header("Content-Type", "text/event-stream; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    last = 0
    try:
        while True:
            try:
                m = os.path.getmtime(DATA("status.json"))
            except OSError:
                m = 0
            if m != last:
                last = m
                handler.wfile.write(b"event: refresh\ndata: 1\n\n")
            else:
                handler.wfile.write(b": ping\n\n")
            handler.wfile.flush()
            time.sleep(4)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass

class Handler(BaseHTTPRequestHandler):
    def send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            with open(os.path.join(HERE, "web", "index.html"), encoding="utf-8") as fh:
                page = fh.read()
            for url, local in VENDOR_JS.items():
                if os.path.exists(os.path.join(HERE, "web", local)):
                    page = page.replace(url, local)
            return self.send(200, (SKELETON + page + "</body></html>").encode("utf-8"), "text/html")
        if path == "/history.json":
            return self.send(200, json.dumps(history_cached(), ensure_ascii=False).encode("utf-8"), "application/json")
        if path == "/at":
            qs = parse_qs(urlparse(self.path).query)
            try:
                hours = float(qs.get("h", ["1"])[0])
            except ValueError:
                hours = 1
            row = state_at(hours)
            out = {"t": row["t"], "d": row["d"]} if row else {"t": None, "d": {}}
            return self.send(200, json.dumps(out).encode("utf-8"), "application/json")
        if path == "/export.csv":
            return self.send(200, export_csv(), "text/csv")
        if path == "/stream":
            return stream_events(self)
        if path in STATIC:
            local = {"/status.json": "status.json", "/notes.json": "notes.json"}.get(path) or path.lstrip("/")
            try:
                with open(os.path.join(HERE, "web" if "/" in local else STATE_DIR, local) if not local.startswith("vendor") else os.path.join(HERE, "web", local), "rb") as fh:
                    return self.send(200, fh.read(), STATIC[path])
            except FileNotFoundError:
                if path == "/notes.json":
                    return self.send(200, b"{}", "application/json")
        self.send(404, b"not found", "text/plain")

    def body_json(self):
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size <= 65536:
            raise ValueError("size")
        return json.loads(self.rfile.read(size).decode("utf-8"))

    def do_POST(self):
        try:
            data = self.body_json()
            if self.path == "/notes":
                clean = {}
                for dev, note in data.items():
                    if not re.fullmatch(r"[a-z0-9-]{1,24}", dev) or not isinstance(note, dict):
                        raise ValueError("key")
                    clean[dev] = {k: str(v)[:200] for k, v in note.items() if k in NOTE_KEYS and str(v).strip()}
                save("notes.json", {k: v for k, v in clean.items() if v})
            elif self.path == "/assign":
                mac, did = str(data.get("mac", "")).lower(), str(data.get("id", ""))
                if not re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac) or (did and did not in DEVICE_IDS):
                    raise ValueError("assign")
                m = load("assignments.json", {})
                if did:
                    m[mac] = did
                else:
                    m.pop(mac, None)
                save("assignments.json", m)
                threading.Thread(target=refresh_now, daemon=True).start()
            elif self.path == "/wol":
                did = str(data.get("id", ""))
                mm = dict(KNOWN_MAC)
                mm.update(load("assignments.json", {}))
                id_mac = {}
                for m, i in mm.items():
                    id_mac.setdefault(i, m)
                mac = id_mac.get(did)
                if not mac or not send_wol(mac):
                    raise ValueError("wol")
            else:
                return self.send(404, b"not found", "text/plain")
            self.send(200, b'{"ok":true}', "application/json")
        except Exception:
            self.send(400, b'{"ok":false}', "application/json")

    def log_message(self, *args):
        pass

if __name__ == "__main__":
    load_vendors()
    if not os.path.exists(DATA("history.jsonl")):
        open(DATA("history.jsonl"), "a").close()
    threading.Thread(target=collector_loop, daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()

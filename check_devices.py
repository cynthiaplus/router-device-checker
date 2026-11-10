#!/usr/bin/env python3
"""Ping every address on your router's network and list the devices that are connected,
with their name, manufacturer and (where the device reveals it) exact model."""

import gzip
import os
import platform
import re
import socket
import subprocess
import time
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

SYSTEM = platform.system().lower()
IS_WINDOWS = SYSTEM == "windows"

# Public list of which company owns which MAC address prefix (from the Wireshark project).
MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf.gz"
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".router-device-checker")
MANUF_FILE = os.path.join(CACHE_DIR, "manuf.gz")
MANUF_MAX_AGE = 30 * 24 * 3600  # re-download the list once a month


# --------------------------------------------------------------------------- discovery

def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))  # no data is sent; this just picks the right network card
    ip = s.getsockname()[0]
    s.close()
    return ip


def ping(ip):
    """Return the reply's TTL if the device answers, else None."""
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    result = subprocess.run(cmd, capture_output=True, text=True)
    # On Windows a "Destination host unreachable" reply can still exit 0, so require a TTL
    m = re.search(r"ttl[=:](\d+)", result.stdout, re.IGNORECASE)
    return int(m.group(1)) if result.returncode == 0 and m else None


def arp_devices(prefix):
    """Devices the laptop has recently talked to (catches ones that ignore pings)."""
    out = subprocess.run(["arp", "-a"], capture_output=True, text=True).stdout
    found = {}
    for line in out.splitlines():
        ip_m = re.search(r"\b(\d+\.\d+\.\d+\.\d+)\b", line)
        mac_m = re.search(r"\b((?:[0-9a-fA-F]{1,2}[-:]){5}[0-9a-fA-F]{1,2})\b", line)
        if ip_m and mac_m and ip_m.group(1).startswith(prefix + "."):
            if IS_WINDOWS and "dynamic" not in line.lower():
                continue
            mac = ":".join(p.zfill(2) for p in re.split("[-:]", mac_m.group(1))).lower()
            if mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                found[ip_m.group(1)] = mac
    return found


# --------------------------------------------------------------------------- names

def mdns_name(ip, timeout=1.5):
    """Ask the device for its own name over mDNS/Bonjour (phones, Macs, printers, TVs)."""
    qname = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    query = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for label in qname.split("."):
        query += bytes([len(label)]) + label.encode()
    query += b"\x00\x00\x0c\x00\x01"  # type PTR, class IN
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(query, (ip, 5353))
        data, _ = s.recvfrom(4096)
    except OSError:
        return None
    finally:
        s.close()

    def read_name(pos, depth=0):
        labels = []
        while pos < len(data) and depth < 10:
            n = data[pos]
            if n == 0:
                return labels, pos + 1
            if n & 0xC0 == 0xC0:  # compression pointer
                sub, _ = read_name(((n & 0x3F) << 8) | data[pos + 1], depth + 1)
                return labels + sub, pos + 2
            labels.append(data[pos + 1:pos + 1 + n].decode("utf-8", "replace"))
            pos += 1 + n
        return labels, pos

    try:
        qd, an = int.from_bytes(data[4:6], "big"), int.from_bytes(data[6:8], "big")
        pos = 12
        for _ in range(qd):
            _, pos = read_name(pos)
            pos += 4
        for _ in range(an):
            _, pos = read_name(pos)
            rtype = int.from_bytes(data[pos:pos + 2], "big")
            rdlen = int.from_bytes(data[pos + 8:pos + 10], "big")
            pos += 10
            if rtype == 12:  # PTR
                labels, _ = read_name(pos)
                name = ".".join(labels)
                return name[:-6] if name.endswith(".local") else name
            pos += rdlen
    except (IndexError, ValueError):
        pass
    return None


def device_name(ip):
    """Try the router's DNS, then mDNS/Bonjour, then NetBIOS (Windows PCs)."""
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name and name != ip:
            return name
    except OSError:
        pass
    name = mdns_name(ip)
    if name:
        return name
    if IS_WINDOWS:
        try:
            out = subprocess.run(["nbtstat", "-A", ip], capture_output=True, text=True,
                                 timeout=6).stdout
            m = re.search(r"^\s*(\S+)\s+<00>\s+UNIQUE", out, re.MULTILINE)
            if m:
                return m.group(1)
        except (OSError, subprocess.TimeoutExpired):
            pass
    return None


# --------------------------------------------------------------------------- manufacturer

def load_manufacturers():
    """Return {(prefix_bits, hex_prefix): company}. Downloads the list once, then caches it."""
    fresh = os.path.exists(MANUF_FILE) and time.time() - os.path.getmtime(MANUF_FILE) < MANUF_MAX_AGE
    if not fresh:
        try:
            req = urllib.request.Request(MANUF_URL, headers={"User-Agent": "router-device-checker"})
            data = urllib.request.urlopen(req, timeout=30).read()
            os.makedirs(CACHE_DIR, exist_ok=True)
            with open(MANUF_FILE, "wb") as f:
                f.write(data)
        except OSError:
            if not os.path.exists(MANUF_FILE):
                print("  (Couldn't download the manufacturer list - no internet? "
                      "Manufacturers will show as unknown.)")
                return {}
    table = {}
    with gzip.open(MANUF_FILE, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 2:
                continue
            prefix, bits = parts[0].strip(), 24
            if "/" in prefix:
                prefix, b = prefix.split("/")
                bits = int(b)
            hexstr = prefix.replace(":", "").replace("-", "").upper()
            company = (parts[2] if len(parts) > 2 and parts[2].strip() else parts[1]).strip()
            table[(bits, hexstr[:bits // 4])] = company
    return table


def manufacturer(mac, table):
    if not mac:
        return None
    if int(mac[1], 16) & 2:
        return "hidden (private MAC address)"
    hexstr = mac.replace(":", "").upper()
    for bits in (36, 28, 24):
        company = table.get((bits, hexstr[:bits // 4]))
        if company:
            return shorten_company(company)
    return None


def shorten_company(name):
    name = re.sub(r"[,.]?\s*(Co\.?,?\s*Ltd\.?|Inc\.?|Corporation|Corp\.?|Limited|Ltd\.?|"
                  r"LLC|GmbH|S\.?A\.?|Technologies|Technology|Electronics|"
                  r"International|Industrial|Development)\b", "", name, flags=re.IGNORECASE)
    return re.sub(r"\s{2,}", " ", name).strip(" ,.") or name


# --------------------------------------------------------------------------- exact model

def upnp_models(local_ip, wait=4):
    """Ask devices to announce themselves over UPnP. TVs, printers, consoles and routers
    usually reply with their exact manufacturer and model."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind((local_ip, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
        s.settimeout(0.5)
        for target in ("ssdp:all", "upnp:rootdevice"):
            msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                   f"MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {target}\r\n\r\n")
            s.sendto(msg.encode(), ("239.255.255.250", 1900))
        locations = {}
        end = time.time() + wait
        while time.time() < end:
            try:
                data, (ip, _) = s.recvfrom(4096)
            except socket.timeout:
                continue
            for line in data.decode(errors="replace").splitlines():
                if line.lower().startswith("location:"):
                    locations.setdefault(ip, set()).add(line.split(":", 1)[1].strip())
    except OSError:
        return {}
    finally:
        s.close()

    def describe(ip):
        for url in locations[ip]:
            try:
                xml = urllib.request.urlopen(url, timeout=4).read()
                root = ET.fromstring(xml)
            except (OSError, ET.ParseError, ValueError):
                continue
            info = {}
            for el in root.iter():
                tag = el.tag.split("}")[-1]
                if tag in ("friendlyName", "manufacturer", "modelName", "modelNumber") \
                        and el.text and tag not in info:
                    info[tag] = el.text.strip()
            if info:
                return ip, info
        return ip, None

    with ThreadPoolExecutor(max_workers=20) as pool:
        return {ip: info for ip, info in pool.map(describe, locations) if info}


def this_computer_model():
    """Make and model of the computer running the script."""
    try:
        if IS_WINDOWS:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "$c = Get-CimInstance Win32_ComputerSystem; \"$($c.Manufacturer)|$($c.Model)\""],
                capture_output=True, text=True, timeout=20).stdout.strip()
            maker, _, model = out.partition("|")
            return maker.strip(), model.strip()
        if SYSTEM == "darwin":
            model = subprocess.run(["sysctl", "-n", "hw.model"], capture_output=True,
                                   text=True, timeout=5).stdout.strip()
            return "Apple", model
        with open("/sys/class/dmi/id/sys_vendor") as f:
            maker = f.read().strip()
        with open("/sys/class/dmi/id/product_name") as f:
            return maker, f.read().strip()
    except (OSError, subprocess.TimeoutExpired):
        return None, None


MODEL_HINTS = [  # (pattern in device name, what it is)
    (r"iphone", "Apple iPhone"), (r"ipad", "Apple iPad"), (r"macbook", "Apple MacBook"),
    (r"imac", "Apple iMac"), (r"apple-?tv", "Apple TV"), (r"watch", "Smartwatch"),
    (r"galaxy|^sm-[a-z]\d", "Samsung Galaxy"), (r"pixel", "Google Pixel"),
    (r"redmi|xiaomi|poco", "Xiaomi phone"), (r"huawei|honor", "Huawei/Honor phone"),
    (r"oppo|realme|oneplus|vivo", "Android phone"), (r"android", "Android device"),
    (r"^hp|laserjet|deskjet|officejet|envy", "HP printer/PC"), (r"epson", "Epson printer"),
    (r"canon", "Canon printer"), (r"brother", "Brother printer"),
    (r"^desktop-|^laptop-", "Windows PC"), (r"playstation|ps[45]", "PlayStation"),
    (r"xbox", "Xbox"), (r"chromecast", "Google Chromecast"), (r"echo|alexa", "Amazon Echo"),
    (r"tv|bravia|webos|tizen", "Smart TV"),
]


def model_from_name(name):
    if not name:
        return None
    for pattern, what in MODEL_HINTS:
        if re.search(pattern, name, re.IGNORECASE):
            return what
    return None


def guess_type(maker, ttl, is_router):
    if is_router:
        return "Router"
    maker = (maker or "").lower()
    if maker.startswith("hidden"):
        return "Phone, tablet or laptop (uses a private MAC address)"
    if "apple" in maker:
        return "Apple device (iPhone, iPad, Mac...)"
    for key, what in [("samsung", "Samsung device (phone, tablet or TV)"),
                      ("hp", "HP device (printer or PC)"), ("hewlett", "HP device (printer or PC)"),
                      ("espressif", "Smart home gadget (plug, bulb, camera...)"),
                      ("tuya", "Smart home gadget"), ("amazon", "Amazon device (Echo, Fire TV...)"),
                      ("google", "Google device (Nest, Chromecast...)"), ("sony", "Sony device"),
                      ("lg ", "LG device (TV or phone)"), ("xiaomi", "Xiaomi device"),
                      ("huawei", "Huawei device"), ("intel", "PC or laptop"),
                      ("realtek", "PC or laptop"), ("tp-link", "Network device (TP-Link)")]:
        if key in maker + " ":
            return what
    if ttl and ttl > 64:
        return "Windows PC"
    return None


# --------------------------------------------------------------------------- main

def main():
    my_ip = get_my_ip()
    prefix = my_ip.rsplit(".", 1)[0]          # e.g. 192.168.1
    addresses = [f"{prefix}.{i}" for i in range(1, 255)]
    router_ip = f"{prefix}.1"

    print(f"Your laptop: {my_ip}")
    print(f"Pinging {prefix}.1 - {prefix}.254 ...")

    with ThreadPoolExecutor(max_workers=100) as pool:
        pinged = {ip: ttl for ip, ttl in zip(addresses, pool.map(ping, addresses)) if ttl}

    macs = arp_devices(prefix)
    found = sorted(set(pinged) | set(macs) | {my_ip}, key=lambda x: int(x.rsplit(".", 1)[1]))

    print("Looking up names, manufacturers and models...\n")
    with ThreadPoolExecutor(max_workers=60) as pool:
        names_job = pool.map(device_name, found)
        upnp_job = pool.submit(upnp_models, my_ip)
        table_job = pool.submit(load_manufacturers)
        names = dict(zip(found, names_job))
        upnp = upnp_job.result()
        table = table_job.result()
    names[my_ip] = socket.gethostname()
    my_maker, my_model = this_computer_model()

    print("=" * 70)
    for ip in found:
        mac = macs.get(ip)
        info = upnp.get(ip, {})
        is_router = ip == router_ip

        if ip == my_ip:
            label, maker, model = "THIS LAPTOP", my_maker, my_model
        else:
            label = "ROUTER" if is_router else ""
            maker = info.get("manufacturer") or manufacturer(mac, table)
            model = " ".join(filter(None, [info.get("modelName"), info.get("modelNumber")])) \
                or model_from_name(names[ip])
        name = info.get("friendlyName") or names[ip]
        kind = None if ip == my_ip else guess_type(maker, pinged.get(ip), is_router)

        print(f"{ip}   {label}")
        print(f"   Name:          {name or '(unknown)'}")
        print(f"   Manufacturer:  {maker or '(unknown)'}")
        print(f"   Exact model:   {model or '(not revealed by the device)'}")
        if kind:
            print(f"   Probably:      {kind}")
        if mac:
            print(f"   MAC address:   {mac}")
        same = [o for o in found if o != ip and mac and macs.get(o) == mac]
        if same:
            print(f"   Note:          same device as {', '.join(same)}")
        if ip not in pinged and ip != my_ip:
            print("   Note:          didn't answer ping, but was seen on the network")
        print("-" * 70)

    unique = {macs.get(ip, ip) for ip in found}
    print(f"\nIP addresses in use: {len(found)}")
    print(f"Devices connected:   {len(unique)}  (addresses sharing a MAC counted once)")
    try:
        input("\nPress Enter to close...")
    except EOFError:
        pass


if __name__ == "__main__":
    main()

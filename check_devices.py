#!/usr/bin/env python3
"""Ping every address on your router's network and list the devices that are connected."""

import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

IS_WINDOWS = platform.system().lower() == "windows"


def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))  # no data is sent; this just picks the right network card
    ip = s.getsockname()[0]
    s.close()
    return ip


def ping(ip):
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    result = subprocess.run(cmd, capture_output=True, text=True)
    # On Windows a "Destination host unreachable" reply can still exit 0, so require "TTL="
    ok = result.returncode == 0 and (not IS_WINDOWS or "TTL=" in result.stdout.upper())
    return ip if ok else None


def arp_devices(prefix):
    """Devices the laptop has recently talked to (catches ones that ignore pings)."""
    out = subprocess.run(["arp", "-a"], capture_output=True, text=True).stdout
    found = {}
    for line in out.splitlines():
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+((?:[0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2})\s+dynamic", line)
        if m and m.group(1).startswith(prefix + "."):
            found[m.group(1)] = m.group(2).replace("-", ":").lower()
    return found


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
    return "(unknown)"


def main():
    my_ip = get_my_ip()
    prefix = my_ip.rsplit(".", 1)[0]          # e.g. 192.168.1
    addresses = [f"{prefix}.{i}" for i in range(1, 255)]

    print(f"Your laptop: {my_ip}")
    print(f"Pinging {prefix}.1 - {prefix}.254 ...\n")

    with ThreadPoolExecutor(max_workers=100) as pool:
        pinged = {ip for ip in pool.map(ping, addresses) if ip}

    macs = arp_devices(prefix)
    found = sorted(pinged | set(macs) | {my_ip}, key=lambda x: int(x.rsplit(".", 1)[1]))

    print("Looking up device names...\n")
    with ThreadPoolExecutor(max_workers=50) as pool:
        names = dict(zip(found, pool.map(device_name, found)))
    names[my_ip] = socket.gethostname()

    print(f"  {'IP ADDRESS':<16}{'DEVICE NAME':<28}{'MAC ADDRESS':<19}NOTES")
    print("  " + "-" * 80)
    for ip in found:
        notes = []
        if ip == my_ip:
            notes.append("this laptop")
        elif ip.endswith(".1"):
            notes.append("probably the router")
        if ip not in pinged and ip != my_ip:
            notes.append("didn't answer ping")
        mac = macs.get(ip, "-" if ip != my_ip else "")
        if mac and mac != "-":
            if int(mac[1], 16) & 2:
                notes.append("private MAC - likely phone/tablet")
            same = [o for o in found if o != ip and macs.get(o) == mac]
            if same:
                notes.append("same device as " + ", ".join(same))
        print(f"  {ip:<16}{names[ip][:27]:<28}{mac:<19}{', '.join(notes)}")

    unique = {macs.get(ip, ip) for ip in found}
    print(f"\nIP addresses in use: {len(found)}")
    print(f"Devices connected:   {len(unique)}  (addresses sharing a MAC counted once)")
    try:
        input("\nPress Enter to close...")
    except EOFError:
        pass


if __name__ == "__main__":
    main()

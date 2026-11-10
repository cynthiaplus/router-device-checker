# Router Device Checker

A small Python script that lists the devices connected to your home router (Wi-Fi network).

## What it shows

- **IP address** of every device on your network
- **Device name**, when the device or router shares it (checks DNS, mDNS/Bonjour and NetBIOS)
- **Manufacturer** (e.g. HP, Apple, Samsung, Huawei), looked up from the MAC address using
  [Wireshark's public manufacturer list](https://www.wireshark.org/download/automated/data/manuf.gz).
  The list is downloaded once and saved in `~/.router-device-checker/`. No device information is sent anywhere.
- **Exact model**, when the device reveals it over UPnP (TVs, printers, consoles, routers) or in
  its name (e.g. "Alexs-iPhone"), plus the exact make and model of the computer running the script
- **A best guess at the device type** (router, Windows PC, Apple device, phone/tablet, smart home gadget...)
- **MAC address** (the device's hardware ID)
- Notes, such as which device is the router, which is your computer, and which ones use a private (randomized) MAC address, which phones and tablets do
- A count of connected devices, with several addresses that belong to one device counted once

## How it works

1. Finds your computer's IP address, for example `192.168.1.23`.
2. Pings every address from `.1` to `.254` on that network, all at once.
3. Reads your computer's ARP table to also catch devices that ignore pings.
4. Looks up a name for each device.

## Usage

You need Python 3. There is nothing else to install.

```
python check_devices.py
```

Works on Windows, macOS and Linux. A scan takes about 10–20 seconds.

## Example output

```
192.168.1.1   ROUTER
   Name:          (unknown)
   Manufacturer:  Huawei
   Exact model:   (not revealed by the device)
   Probably:      Router
   MAC address:   ec:c0:1b:11:22:33
----------------------------------------------------------------------
192.168.1.23   THIS LAPTOP
   Name:          my-laptop
   Manufacturer:  HP
   Exact model:   HP Laptop 15
----------------------------------------------------------------------
192.168.1.40
   Name:          (unknown)
   Manufacturer:  hidden (private MAC address)
   Exact model:   (not revealed by the device)
   Probably:      Phone, tablet or laptop (uses a private MAC address)
   MAC address:   8a:12:34:56:78:9a
----------------------------------------------------------------------

IP addresses in use: 3
Devices connected:   3  (addresses sharing a MAC counted once)
```

## Limitations

- Devices that are asleep, or that block pings, may be missed.
- Modern phones, tablets and laptops use a **private (randomized) MAC address**, which hides
  their manufacturer. Their exact model can only be seen if they announce it themselves.
- Many phones and smart devices don't share their name on the network. For the most complete list with names, check your router's admin page, usually at http://192.168.1.1 or http://192.168.0.1.
- Only scan networks you own or have permission to scan.

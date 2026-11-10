# Router Device Checker

A small Python script that lists the devices connected to your home router (Wi-Fi network).

## What it shows

- **IP address** of every device on your network
- **Device name**, when the device or router shares it (checks DNS, mDNS/Bonjour and NetBIOS)
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
  IP ADDRESS      DEVICE NAME                 MAC ADDRESS        NOTES
  --------------------------------------------------------------------------------
  192.168.1.1     (unknown)                   aa:bb:cc:11:22:33  probably the router
  192.168.1.23    my-laptop                                      this laptop
  192.168.1.40    (unknown)                   8a:12:34:56:78:9a  private MAC - likely phone/tablet

IP addresses in use: 3
Devices connected:   3  (addresses sharing a MAC counted once)
```

## Limitations

- Devices that are asleep, or that block pings, may be missed.
- Many phones and smart devices don't share their name on the network. For the most complete list with names, check your router's admin page, usually at http://192.168.1.1 or http://192.168.0.1.
- Only scan networks you own or have permission to scan.
